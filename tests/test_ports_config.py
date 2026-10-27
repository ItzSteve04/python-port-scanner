"""Port syntax and enforced safety/resource boundaries."""

import unittest

from port_scanner.models import ScanConfig
from port_scanner.ports import COMMON_PORTS, parse_ports


class PortParsingTests(unittest.TestCase):
    def test_mixed_ranges_sorted_deduplicated(self):
        self.assertEqual(parse_ports("443, 20-23,22,80"), (20, 21, 22, 23, 80, 443))

    def test_full_port_range(self):
        self.assertEqual(len(parse_ports("1-65535")), 65535)

    def test_single_port_and_whitespace(self):
        self.assertEqual(parse_ports(" 65535 "), (65535,))
        self.assertEqual(parse_ports("1 - 3"), (1, 2, 3))

    def test_invalid_specs(self):
        for value in (
            "",
            "0",
            "65536",
            "-1",
            "80,",
            ",80",
            "10-1",
            "80,,443",
            "http",
            "1-2-3",
            "1.5",
            "1;2",
            "1 2",
            "+80",
            "１",
            "1e2",
            "100000",
        ):
            with self.subTest(spec=value), self.assertRaises(ValueError):
                parse_ports(value)

    def test_oversized_spec(self):
        with self.assertRaises(ValueError):
            parse_ports("1," * 200_001)

    def test_common_ports_are_valid_unique_and_sorted(self):
        self.assertEqual(COMMON_PORTS, tuple(sorted(set(COMMON_PORTS))))
        self.assertTrue({22, 80, 443, 3389}.issubset(COMMON_PORTS))


class ConfigTests(unittest.TestCase):
    def test_defaults(self):
        config = ScanConfig("LOCALHOST")
        self.assertEqual(config.target, "localhost")
        self.assertEqual(config.workers, 32)
        self.assertFalse(config.authorized)
        self.assertFalse(config.banner)

    def test_ports_are_immutable_sorted_and_deduplicated(self):
        self.assertEqual(ScanConfig("127.0.0.1", ports=(80, 22, 80)).ports, (22, 80))

    def test_numeric_limits(self):
        cases = {
            "workers": (0, 129, True, 1.5),
            "timeout": (0, 10.1, float("nan"), float("inf"), True),
            "rate": (0.9, 200.1, float("nan"), -1),
            "banner_timeout": (0.01, 5.1),
            "banner_bytes": (0, 4097, True),
            "family": ("udp",),
            "authorized": ("yes",),
            "banner": (1,),
        }
        for key, values in cases.items():
            for value in values:
                with self.subTest(key=key, value=value), self.assertRaises(ValueError):
                    ScanConfig("localhost", **{key: value})

    def test_port_limits_for_library_callers(self):
        for ports in ((), (0,), (65536,), (True,), (80.0,)):
            with self.subTest(ports=ports), self.assertRaises(ValueError):
                ScanConfig("localhost", ports=ports)

    def test_boundary_values_are_allowed(self):
        config = ScanConfig(
            "localhost", timeout=0.05, workers=128, rate=200, banner_timeout=5, banner_bytes=4096
        )
        self.assertEqual(config.rate, 200)

    def test_frozen_configuration(self):
        with self.assertRaises(AttributeError):
            ScanConfig("localhost").workers = 100


if __name__ == "__main__":
    unittest.main()
