"""Untrusted banner handling and auditable service-hint provenance."""

import unittest
from unittest.mock import MagicMock, patch

from port_scanner.banner import grab_banner, safe_text
from port_scanner.ports import COMMON_PORTS
from port_scanner.services import ServiceRegistry


class BannerTests(unittest.TestCase):
    def test_control_characters_are_escaped(self):
        self.assertEqual(
            safe_text("\x1b[31mhello\r\n\x00\u202e"), "\\x1b[31mhello\\x0d\\x0a\\x00\\u202e"
        )
        self.assertEqual(safe_text("\\x1b"), "\\\\x1b")
        self.assertEqual(safe_text("café"), "café")

    def test_success_and_invalid_utf8(self):
        connection = MagicMock()
        connection.recv.return_value = b"SSH-2.0-test\xff\r\n"
        result = grab_banner(connection, 0.2, 512)
        self.assertEqual(result.status, "received")
        self.assertIn("�", result.text)
        self.assertEqual(result.bytes_received, 15)
        connection.settimeout.assert_called_once_with(0.2)
        connection.recv.assert_called_once_with(512)
        connection.send.assert_not_called()
        connection.sendall.assert_not_called()

    def test_timeout_empty_and_reset(self):
        for outcome, status in (
            (TimeoutError(), "timeout"),
            (b"", "empty"),
            (ConnectionResetError(), "error"),
        ):
            with self.subTest(status=status):
                connection = MagicMock()
                if isinstance(outcome, bytes):
                    connection.recv.return_value = outcome
                else:
                    connection.recv.side_effect = outcome
                self.assertEqual(grab_banner(connection, 0.1, 10).status, status)

    def test_byte_limit_is_reported(self):
        connection = MagicMock()
        connection.recv.return_value = b"a" * 32
        result = grab_banner(connection, 0.1, 32)
        self.assertTrue(result.at_limit)
        self.assertEqual(result.bytes_received, 32)

    def test_settimeout_failure_is_banner_error(self):
        connection = MagicMock()
        connection.settimeout.side_effect = OSError("closed")
        self.assertEqual(grab_banner(connection, 0.1, 32).status, "error")


class ServiceTests(unittest.TestCase):
    def test_common_ports_have_curated_hints(self):
        registry = ServiceRegistry()
        for port in COMMON_PORTS:
            with self.subTest(port=port):
                self.assertEqual(registry.identify(port).source, "curated")
        self.assertEqual(registry.identify(22).name, "ssh")

    @patch("port_scanner.services.socket.getservbyport", return_value="local-service")
    def test_system_fallback_is_tcp(self, lookup):
        hint = ServiceRegistry().identify(65000)
        self.assertEqual((hint.name, hint.source), ("local-service", "system"))
        lookup.assert_called_once_with(65000, "tcp")

    @patch("port_scanner.services.socket.getservbyport", side_effect=OSError())
    def test_unknown_fallback(self, _lookup):
        self.assertEqual(ServiceRegistry().identify(65000).source, "unknown")


if __name__ == "__main__":
    unittest.main()
