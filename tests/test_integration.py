"""Real TCP and CLI tests, exclusively on IPv4/IPv6 loopback."""

import csv
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

from port_scanner import PortState, ScanConfig, TCPScanner
from tests.helpers import local_server, non_listening_port


class LocalhostIntegrationTests(unittest.TestCase):
    def test_open_and_non_listening_ports(self):
        with local_server() as opened, non_listening_port() as non_listening:
            report = TCPScanner(
                ScanConfig(
                    "127.0.0.1",
                    ports=(opened, non_listening),
                    timeout=0.2,
                    rate=200,
                    authorized=True,
                )
            ).scan()
        states = {result.port: result.state for result in report.results}
        self.assertEqual(states[opened], PortState.OPEN)
        # A reserved, non-listening port cannot connect successfully. Windows can
        # exhaust this short timeout before delivering an explicit refusal.
        # Exact Winsock refusal/timeout classification is tested with known codes
        # in ProbeTests, independently of the local TCP stack's response timing.
        self.assertIn(states[non_listening], (PortState.CLOSED, PortState.TIMED_OUT))
        self.assertEqual(report.counts["open"], 1)
        self.assertEqual(report.counts["closed"] + report.counts["timed_out"], 1)
        self.assertEqual(len(report.results), 2)
        self.assertFalse(report.interrupted)

    def test_hostname_resolution(self):
        with local_server() as port:
            report = TCPScanner(
                ScanConfig("localhost", ports=(port,), family="ipv4", authorized=True)
            ).scan()
        self.assertEqual(report.results[0].state, PortState.OPEN)
        self.assertEqual(report.target.ip, "127.0.0.1")

    def test_banner_on_local_service(self):
        with local_server(b"SSH-2.0-LocalTest\r\n") as port:
            report = TCPScanner(
                ScanConfig("127.0.0.1", ports=(port,), banner=True, authorized=True)
            ).scan()
        result = report.results[0]
        self.assertEqual(result.banner.status, "received")
        self.assertEqual(result.banner.text, "SSH-2.0-LocalTest\\x0d\\x0a")
        self.assertEqual(result.state, PortState.OPEN)

    def test_silent_service_does_not_exceed_banner_timeout(self):
        with local_server(None) as port:
            report = TCPScanner(
                ScanConfig(
                    "127.0.0.1", ports=(port,), banner=True, banner_timeout=0.1, authorized=True
                )
            ).scan()
        self.assertEqual(report.results[0].state, PortState.OPEN)
        self.assertEqual(report.results[0].banner.status, "timeout")
        self.assertLess(report.duration_seconds, 2)

    def test_large_banner_is_capped(self):
        with local_server(b"A" * 4096) as port:
            report = TCPScanner(
                ScanConfig(
                    "127.0.0.1", ports=(port,), banner=True, banner_bytes=64, authorized=True
                )
            ).scan()
        self.assertEqual(report.results[0].banner.bytes_received, 64)
        self.assertTrue(report.results[0].banner.at_limit)

    def test_rate_limit_is_global_across_workers(self):
        with non_listening_port() as p1, non_listening_port() as p2, non_listening_port() as p3:
            report = TCPScanner(
                ScanConfig("127.0.0.1", ports=(p1, p2, p3), workers=3, rate=10, authorized=True)
            ).scan()
        self.assertGreaterEqual(report.duration_seconds, 0.18)
        self.assertLess(report.duration_seconds, 3)

    def test_ipv6_loopback_when_available(self):
        if not socket.has_ipv6:
            self.skipTest("IPv6 is unavailable on this platform")
        try:
            with local_server(family=socket.AF_INET6) as port:
                report = TCPScanner(
                    ScanConfig("::1", ports=(port,), family="ipv6", authorized=True)
                ).scan()
        except OSError as exc:
            self.skipTest(f"IPv6 loopback unavailable: {exc}")
        self.assertEqual(report.results[0].state, PortState.OPEN)
        self.assertEqual(report.target.family_name, "ipv6")

    def test_cli_exports_both_formats(self):
        with tempfile.TemporaryDirectory() as directory, local_server() as port:
            json_path = Path(directory) / "scan.json"
            csv_path = Path(directory) / "scan.csv"
            completed = subprocess.run(
                [
                    sys.executable,
                    "-m",
                    "port_scanner",
                    "127.0.0.1",
                    "-p",
                    str(port),
                    "--authorized",
                    "--banner",
                    "--json",
                    str(json_path),
                    "--csv",
                    str(csv_path),
                ],
                capture_output=True,
                text=True,
                timeout=10,
                check=False,
            )
            self.assertEqual(completed.returncode, 0, completed.stderr)
            self.assertIn("COMPLETE", completed.stdout)
            self.assertIn("Progress: 1/1", completed.stderr)
            self.assertEqual(json.loads(json_path.read_text())["summary"]["open"], 1)
            with csv_path.open(newline="") as stream:
                self.assertEqual(list(csv.DictReader(stream))[0]["state"], "open")

    def test_cli_noninteractive_auth_is_required(self):
        completed = subprocess.run(
            [sys.executable, "-m", "port_scanner", "127.0.0.1", "-p", "1"],
            input="",
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertIn("Authorization required", completed.stderr)

    def test_cli_invalid_target_returns_usage_error(self):
        completed = subprocess.run(
            [sys.executable, "-m", "port_scanner", "999.0.0.1", "--authorized"],
            capture_output=True,
            text=True,
            timeout=10,
            check=False,
        )
        self.assertEqual(completed.returncode, 2)
        self.assertNotIn("Traceback", completed.stderr)

    @unittest.skipIf(
        os.name == "nt", "POSIX SIGINT subprocess delivery; Windows uses manual Ctrl+C"
    )
    def test_sigint_exports_partial_results_and_returns_130(self):
        with tempfile.TemporaryDirectory() as directory, local_server(None) as port:
            path = Path(directory) / "partial.json"
            ports = f"{port},1-100"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "port_scanner",
                    "127.0.0.1",
                    "--authorized",
                    "-p",
                    ports,
                    "--rate",
                    "1",
                    "--workers",
                    "2",
                    "--json",
                    str(path),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            try:
                # The first flushed line precedes signal-handler installation by only
                # a few instructions; give startup a bounded margin before signalling.
                self.assertIn("Authorized target", process.stdout.readline())
                time.sleep(0.15)
                process.send_signal(signal.SIGINT)
                stdout, stderr = process.communicate(timeout=5)
            finally:
                if process.poll() is None:
                    process.kill()
                    process.communicate()
            self.assertEqual(process.returncode, 130, stdout + stderr)
            document = json.loads(path.read_text())
            self.assertTrue(document["interrupted"])
            self.assertGreater(document["summary"]["unscanned"], 0)
            self.assertEqual(
                document["summary"]["completed"] + document["summary"]["unscanned"],
                document["summary"]["requested"],
            )


if __name__ == "__main__":
    unittest.main()
