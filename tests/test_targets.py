"""Single-target validation, resolution selection, and IPv6 endpoint handling."""

import socket
import unittest
from unittest.mock import patch

from port_scanner.targets import TargetError, normalize_target, resolve_target

V4 = (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("127.0.0.1", 0))
V6 = (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("::1", 0, 0, 0))


class TargetTests(unittest.TestCase):
    def test_normalize_names_and_ip(self):
        self.assertEqual(normalize_target("LOCALHOST."), "localhost.")
        self.assertEqual(normalize_target("2001:0db8::1"), "2001:db8::1")
        self.assertEqual(normalize_target("bücher.example"), "xn--bcher-kva.example")

    def test_invalid_targets(self):
        for target in (
            "",
            " localhost",
            "host name",
            "https://localhost",
            "127.0.0.0/24",
            "localhost:80",
            "999.1.1.1",
            "1.2.3",
            "[::1]",
            "a..b",
            "example..",
            "-host",
            "host_1",
            "a" * 64 + ".test",
            "a" * 255,
            "host\x00",
            "host\nname",
            "name@host",
            "bad%host",
            "::invalid",
        ):
            with self.subTest(target=target), self.assertRaises(TargetError):
                normalize_target(target)

    def test_rejects_non_unicast(self):
        for target in (
            "0.0.0.0",
            "::",
            "224.0.0.1",
            "ff02::1",
            "255.255.255.255",
            "::ffff:0.0.0.0",
            "::ffff:224.0.0.1",
        ):
            with self.subTest(target=target), self.assertRaises(TargetError):
                normalize_target(target)

    @patch("port_scanner.targets.socket.getaddrinfo", return_value=[V6, V4, V4])
    def test_auto_prefers_ipv4_and_deduplicates(self, resolver):
        target = resolve_target("localhost")
        self.assertEqual(target.ip, "127.0.0.1")
        self.assertEqual(target.addresses, ("127.0.0.1", "::1"))
        self.assertEqual(target.endpoint(80), ("127.0.0.1", 80))
        self.assertEqual(target.family_name, "ipv4")
        resolver.assert_called_once()

    @patch("port_scanner.targets.socket.getaddrinfo", return_value=[V6])
    def test_explicit_ipv6(self, resolver):
        target = resolve_target("localhost", "ipv6")
        self.assertEqual(target.endpoint(443), ("::1", 443, 0, 0))
        self.assertEqual(target.family_name, "ipv6")
        self.assertEqual(resolver.call_args.args[2], socket.AF_INET6)

    @patch(
        "port_scanner.targets.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET6, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("fe80::1", 0, 0, 7)),
        ],
    )
    def test_scoped_ipv6(self, _resolver):
        self.assertEqual(resolve_target("fe80::1%7", "ipv6").endpoint(22), ("fe80::1", 22, 0, 7))

    @patch("port_scanner.targets.socket.getaddrinfo", side_effect=socket.gaierror("not found"))
    def test_failed_resolution(self, _resolver):
        with self.assertRaisesRegex(TargetError, "Cannot resolve"):
            resolve_target("missing.invalid")

    @patch("port_scanner.targets.socket.getaddrinfo", return_value=[])
    def test_empty_resolution(self, _resolver):
        with self.assertRaisesRegex(TargetError, "No usable TCP"):
            resolve_target("missing.invalid")

    @patch(
        "port_scanner.targets.socket.getaddrinfo",
        return_value=[
            (socket.AF_INET, socket.SOCK_STREAM, socket.IPPROTO_TCP, "", ("0.0.0.0", 0)),
        ],
    )
    def test_resolution_cannot_bypass_unicast_check(self, _resolver):
        with self.assertRaises(TargetError):
            resolve_target("localhost")

    @patch("port_scanner.targets.socket.getaddrinfo")
    def test_invalid_family_does_not_resolve(self, resolver):
        with self.assertRaises(TargetError):
            resolve_target("localhost", "udp")
        resolver.assert_not_called()


if __name__ == "__main__":
    unittest.main()
