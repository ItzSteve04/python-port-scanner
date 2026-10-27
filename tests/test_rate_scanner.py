"""Worker behavior, cancellation, and global connection pacing."""

import errno
import socket
import threading
import time
import unittest
from concurrent.futures import wait as real_wait
from unittest.mock import MagicMock, patch

from port_scanner.models import PortResult, PortState, ScanConfig
from port_scanner.rate_limit import RateLimiter
from port_scanner.scanner import (
    AuthorizationError,
    TCPScanner,
    classify_error,
    describe_connect_error,
)
from port_scanner.targets import ResolvedTarget

TARGET = ResolvedTarget("localhost", "127.0.0.1", socket.AF_INET, ("127.0.0.1",))


class RateLimiterTests(unittest.TestCase):
    def test_permits_have_spacing_and_no_accumulated_burst(self):
        clock = [10.0]
        delays = []
        stop = MagicMock()

        def advance(delay):
            delays.append(delay)
            clock[0] += delay
            return False

        stop.wait.side_effect = advance
        with patch("port_scanner.rate_limit.time.monotonic", side_effect=lambda: clock[0]):
            limiter = RateLimiter(10)
            self.assertTrue(limiter.acquire(stop))
            self.assertTrue(limiter.acquire(stop))
            clock[0] += 5
            self.assertTrue(limiter.acquire(stop))
            self.assertTrue(limiter.acquire(stop))
        self.assertEqual(delays[0], 0)
        self.assertAlmostEqual(delays[1], 0.1)
        self.assertEqual(delays[2], 0)
        self.assertAlmostEqual(delays[3], 0.1)

    def test_cancelled_permit(self):
        stop = threading.Event()
        stop.set()
        self.assertFalse(RateLimiter(1).acquire(stop))


class ErrorClassificationTests(unittest.TestCase):
    def test_error_categories_include_winsock(self):
        for code, expected in (
            (errno.ECONNREFUSED, PortState.CLOSED),
            (10061, PortState.CLOSED),
            (errno.ETIMEDOUT, PortState.TIMED_OUT),
            (10060, PortState.TIMED_OUT),
            (10035, PortState.TIMED_OUT),
            (errno.EAGAIN, PortState.TIMED_OUT),
            (errno.EHOSTUNREACH, PortState.UNREACHABLE),
            (errno.ENETUNREACH, PortState.UNREACHABLE),
            (10051, PortState.UNREACHABLE),
            (errno.EMFILE, PortState.ERROR),
            (errno.EACCES, PortState.ERROR),
        ):
            with self.subTest(code=code):
                self.assertEqual(classify_error(code), expected)

    def test_winsock_codes_do_not_use_posix_error_messages(self):
        with patch("port_scanner.scanner.os.strerror") as strerror:
            self.assertIn("WSAEWOULDBLOCK", describe_connect_error(10035))
            self.assertIn("WSAECONNREFUSED", describe_connect_error(10061))
            self.assertIn("WSAETIMEDOUT", describe_connect_error(10060))
        strerror.assert_not_called()

    def test_posix_errors_use_native_description(self):
        with patch("port_scanner.scanner.os.strerror", return_value="Permission denied"):
            self.assertIn("Permission denied", describe_connect_error(errno.EACCES))


class ProbeTests(unittest.TestCase):
    def setUp(self):
        self.scanner = TCPScanner(ScanConfig("localhost", ports=(22,), authorized=True))
        self.scanner._limiter = MagicMock()
        self.scanner._limiter.acquire.return_value = True

    @patch("port_scanner.scanner.socket.socket")
    def test_success_closes_socket_and_uses_pinned_ip(self, factory):
        connection = factory.return_value.__enter__.return_value
        connection.connect_ex.return_value = 0
        result = self.scanner._probe(TARGET, 22)
        self.assertEqual(result.state, PortState.OPEN)
        self.assertIsNone(result.banner)
        connection.connect_ex.assert_called_once_with(("127.0.0.1", 22))
        factory.return_value.__exit__.assert_called_once()
        self.assertGreaterEqual(result.connect_ms, 0)

    @patch("port_scanner.scanner.socket.socket")
    def test_nonzero_connect_results(self, factory):
        connection = factory.return_value.__enter__.return_value
        for code, state in (
            (errno.ECONNREFUSED, PortState.CLOSED),
            (errno.ETIMEDOUT, PortState.TIMED_OUT),
            (errno.ENETUNREACH, PortState.UNREACHABLE),
            (errno.EACCES, PortState.ERROR),
        ):
            with self.subTest(code=code):
                connection.connect_ex.return_value = code
                result = self.scanner._probe(TARGET, 22)
                self.assertEqual(result.state, state)
                self.assertIn(str(code), result.error)

    @patch("port_scanner.scanner.socket.socket")
    def test_winsock_timeout_is_not_reported_as_closed(self, factory):
        connection = factory.return_value.__enter__.return_value
        connection.connect_ex.return_value = 10035
        result = self.scanner._probe(TARGET, 22)
        self.assertEqual(result.state, PortState.TIMED_OUT)
        self.assertIn("connect timeout", result.error)
        self.assertIn("WSAEWOULDBLOCK", result.error)

    @patch("port_scanner.scanner.socket.socket")
    def test_winsock_refusal_remains_closed(self, factory):
        connection = factory.return_value.__enter__.return_value
        connection.connect_ex.return_value = 10061
        result = self.scanner._probe(TARGET, 22)
        self.assertEqual(result.state, PortState.CLOSED)
        self.assertIn("Connection refused", result.error)

    @patch(
        "port_scanner.scanner.socket.socket", side_effect=OSError(errno.EMFILE, "too many files")
    )
    def test_socket_creation_failure(self, _factory):
        self.assertEqual(self.scanner._probe(TARGET, 22).state, PortState.ERROR)

    @patch("port_scanner.scanner.socket.socket")
    def test_timeout_exception(self, factory):
        factory.return_value.__enter__.return_value.connect_ex.side_effect = TimeoutError()
        self.assertEqual(self.scanner._probe(TARGET, 22).state, PortState.TIMED_OUT)

    @patch("port_scanner.scanner.socket.socket")
    def test_socket_exception(self, factory):
        factory.return_value.__enter__.return_value.connect_ex.side_effect = OSError(
            errno.EHOSTUNREACH, "host unreachable"
        )
        self.assertEqual(self.scanner._probe(TARGET, 22).state, PortState.UNREACHABLE)

    @patch("port_scanner.scanner.socket.socket")
    def test_cancelled_worker_does_not_create_socket(self, factory):
        self.scanner.cancel()
        self.assertIsNone(self.scanner._probe(TARGET, 22))
        factory.assert_not_called()

    @patch("port_scanner.scanner.socket.socket")
    def test_banner_timeout_keeps_open_state(self, factory):
        scanner = TCPScanner(ScanConfig("localhost", ports=(22,), banner=True, authorized=True))
        connection = factory.return_value.__enter__.return_value
        connection.connect_ex.return_value = 0
        connection.recv.side_effect = TimeoutError()
        result = scanner._probe(TARGET, 22)
        self.assertEqual(result.state, PortState.OPEN)
        self.assertEqual(result.banner.status, "timeout")


class SchedulingTests(unittest.TestCase):
    @patch("port_scanner.scanner.resolve_target")
    def test_authorization_required_before_dns(self, resolver):
        with self.assertRaises(AuthorizationError):
            TCPScanner(ScanConfig("localhost")).scan()
        resolver.assert_not_called()

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_bounded_parallelism_and_single_resolution(self, resolver):
        scanner = TCPScanner(
            ScanConfig("localhost", ports=tuple(range(1, 21)), workers=3, authorized=True)
        )
        active = [0, 0]
        lock = threading.Lock()

        def probe(_target, port):
            with lock:
                active[0] += 1
                active[1] = max(active)
            time.sleep(0.005)
            with lock:
                active[0] -= 1
            return PortResult(port, PortState.CLOSED, "unknown", "unknown", 0.1)

        progress = []
        with patch.object(scanner, "_probe", side_effect=probe):
            report = scanner.scan(progress.append)
        self.assertEqual(len(report.results), 20)
        self.assertEqual([p.completed for p in progress], list(range(1, 21)))
        self.assertGreater(active[1], 1)
        self.assertLessEqual(active[1], 3)
        resolver.assert_called_once()

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_cancel_from_progress_preserves_partial_observations(self, _resolver):
        scanner = TCPScanner(
            ScanConfig("localhost", ports=(1, 2, 3, 4), workers=1, authorized=True)
        )

        def progress(update):
            if update.completed == 2:
                scanner.cancel()

        with patch.object(
            scanner,
            "_probe",
            side_effect=lambda t, p: PortResult(p, PortState.CLOSED, "unknown", "unknown", 0.1),
        ):
            report = scanner.scan(progress)
        self.assertTrue(report.interrupted)
        self.assertEqual(len(report.results), 2)
        self.assertEqual(report.unscanned_ports, (3, 4))

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_precancelled_scan(self, _resolver):
        scanner = TCPScanner(ScanConfig("localhost", authorized=True))
        scanner.cancel()
        report = scanner.scan()
        self.assertTrue(report.interrupted)
        self.assertEqual(report.results, ())

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_instance_cannot_be_reused(self, _resolver):
        scanner = TCPScanner(ScanConfig("localhost", authorized=True))
        scanner.cancel()
        scanner.scan()
        with self.assertRaisesRegex(RuntimeError, "only be used once"):
            scanner.scan()

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_keyboard_interrupt_during_wait(self, _resolver):
        scanner = TCPScanner(ScanConfig("localhost", ports=(1, 2, 3), workers=1, authorized=True))
        calls = [0]

        def interrupt_once(*args, **kwargs):
            calls[0] += 1
            if calls[0] == 1:
                raise KeyboardInterrupt()
            return real_wait(*args, **kwargs)

        with patch("port_scanner.scanner.wait", side_effect=interrupt_once):
            report = scanner.scan()
        self.assertTrue(report.interrupted)
        self.assertLessEqual(len(report.results), 1)

    @patch("port_scanner.scanner.resolve_target", return_value=TARGET)
    def test_callback_failure_cancels_workers(self, _resolver):
        scanner = TCPScanner(ScanConfig("localhost", ports=(1, 2, 3), workers=1, authorized=True))
        callback = MagicMock(side_effect=RuntimeError("callback failed"))
        with self.assertRaisesRegex(RuntimeError, "callback failed"):
            scanner.scan(callback)
        self.assertTrue(scanner._stop.is_set())


if __name__ == "__main__":
    unittest.main()
