"""CLI usage, explicit authorization, error reporting, and terminal progress."""

import io
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from dataclasses import replace
from pathlib import Path
from unittest.mock import MagicMock, patch

from port_scanner import __version__
from port_scanner.cli import ProgressDisplay, _confirm_authorization, main, print_report
from port_scanner.models import ScanProgress
from port_scanner.targets import TargetError
from tests.helpers import sample_report


class CLITests(unittest.TestCase):
    def setUp(self):
        self.stdout = io.StringIO()
        self.stderr = io.StringIO()
        self.out = redirect_stdout(self.stdout)
        self.err = redirect_stderr(self.stderr)
        self.out.__enter__()
        self.err.__enter__()
        self.addCleanup(self.out.__exit__, None, None, None)
        self.addCleanup(self.err.__exit__, None, None, None)

    def test_help(self):
        with self.assertRaises(SystemExit) as exc:
            main(["--help"])
        self.assertEqual(exc.exception.code, 0)
        self.assertIn("--authorized", self.stdout.getvalue())

    def test_version(self):
        with self.assertRaises(SystemExit) as exc:
            main(["--version"])
        self.assertEqual(exc.exception.code, 0)
        self.assertIn(__version__, self.stdout.getvalue())

    def test_invalid_options(self):
        for arguments in (
            ["--ports", "80,"],
            ["--rate", "201"],
            ["--timeout", "nan"],
            ["--workers", "0"],
            ["--banner-bytes", "4097"],
        ):
            with self.subTest(arguments=arguments), self.assertRaises(SystemExit) as exc:
                main(["127.0.0.1", "--authorized", *arguments])
            self.assertEqual(exc.exception.code, 2)

    @patch("port_scanner.cli.sys.stdin")
    def test_interactive_confirmation_accepts_exact_phrase(self, stdin):
        stdin.isatty.return_value = True
        with patch("builtins.input", return_value="I AM AUTHORIZED"):
            self.assertTrue(_confirm_authorization("localhost"))
        with patch("builtins.input", return_value="yes"):
            self.assertFalse(_confirm_authorization("localhost"))
        with patch("builtins.input", side_effect=EOFError()):
            self.assertFalse(_confirm_authorization("localhost"))

    @patch("port_scanner.cli._confirm_authorization", return_value=False)
    @patch("port_scanner.cli.TCPScanner")
    def test_declined_auth_never_constructs_scanner(self, scanner, _confirm):
        self.assertEqual(main(["localhost"]), 2)
        scanner.assert_not_called()

    @patch("port_scanner.cli._confirm_authorization", return_value=True)
    @patch("port_scanner.cli.TCPScanner")
    def test_confirmed_auth_passed_to_library(self, scanner, _confirm):
        scanner.return_value.scan.return_value = sample_report()
        self.assertEqual(main(["localhost", "--no-progress"]), 0)
        self.assertTrue(scanner.call_args.args[0].authorized)

    def test_same_export_path_is_rejected(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(SystemExit) as exc:
            path = str(Path(directory) / "scan.json")
            main(["localhost", "--authorized", "--json", path, "--csv", path])
        self.assertEqual(exc.exception.code, 2)

    def test_missing_parent_is_rejected_before_scanning(self):
        with tempfile.TemporaryDirectory() as directory, self.assertRaises(SystemExit) as exc:
            main(
                [
                    "localhost",
                    "--authorized",
                    "--json",
                    str(Path(directory) / "missing" / "scan.json"),
                ]
            )
        self.assertEqual(exc.exception.code, 2)

    @patch("port_scanner.cli.TCPScanner")
    def test_dns_failure_has_no_traceback(self, scanner):
        scanner.return_value.scan.side_effect = TargetError("not found")
        self.assertEqual(main(["missing.invalid", "--authorized"]), 1)
        self.assertIn("Scan failed", self.stderr.getvalue())
        self.assertNotIn("Traceback", self.stderr.getvalue())

    @patch("port_scanner.cli.TCPScanner")
    def test_interrupt_before_report(self, scanner):
        scanner.return_value.scan.side_effect = KeyboardInterrupt()
        self.assertEqual(main(["localhost", "--authorized"]), 130)

    @patch("port_scanner.cli.export_json", side_effect=PermissionError("denied"))
    @patch("port_scanner.cli.export_csv")
    @patch("port_scanner.cli.TCPScanner")
    def test_failed_export_still_attempts_other_format(self, scanner, csv_export, _json_export):
        scanner.return_value.scan.return_value = sample_report()
        with tempfile.TemporaryDirectory() as directory:
            self.assertEqual(
                main(
                    [
                        "localhost",
                        "--authorized",
                        "--json",
                        str(Path(directory) / "a"),
                        "--csv",
                        str(Path(directory) / "b"),
                    ]
                ),
                1,
            )
        csv_export.assert_called_once()
        self.assertIn("Cannot export JSON", self.stderr.getvalue())

    @patch("port_scanner.cli.TCPScanner")
    def test_interrupted_report_exit_code(self, scanner):
        scanner.return_value.scan.return_value = sample_report(interrupted=True)
        self.assertEqual(main(["localhost", "--authorized"]), 130)
        self.assertIn("INTERRUPTED", self.stdout.getvalue())

    def test_all_states_printed_when_requested(self):
        print_report(sample_report(), show_all=True)
        self.assertIn("closed", self.stdout.getvalue())
        self.assertIn("refused", self.stdout.getvalue())

    def test_no_observations_prints_clear_message(self):
        print_report(sample_report(results=False))
        self.assertIn("No open TCP ports observed", self.stdout.getvalue())

    def test_multi_address_notice(self):
        report = sample_report()
        report = replace(report, target=replace(report.target, addresses=("127.0.0.1", "::1")))
        print_report(report)
        self.assertIn("scanned only 127.0.0.1", self.stdout.getvalue())


class ProgressTests(unittest.TestCase):
    def test_non_tty_prints_only_final_line(self):
        stream = io.StringIO()
        display = ProgressDisplay(stream)
        display.update(ScanProgress(1, 3, 1))
        self.assertEqual(stream.getvalue(), "")
        display.finish(sample_report())
        self.assertIn("Progress: 2/3", stream.getvalue())

    def test_disabled_progress_has_no_output(self):
        stream = io.StringIO()
        display = ProgressDisplay(stream, enabled=False)
        display.update(ScanProgress(1, 3, 1))
        display.finish(sample_report())
        self.assertEqual(stream.getvalue(), "")

    def test_tty_updates_are_throttled(self):
        stream = MagicMock()
        stream.isatty.return_value = True
        display = ProgressDisplay(stream)
        with patch("port_scanner.cli.time.monotonic", side_effect=[10.0, 10.01, 10.02]):
            display.update(ScanProgress(1, 3, 1))
            display.update(ScanProgress(2, 3, 1))
            display.update(ScanProgress(3, 3, 1))
        self.assertEqual(stream.write.call_count, 2)
        display.finish(sample_report())
        self.assertTrue(stream.write.call_args.args[0].endswith("\n"))


if __name__ == "__main__":
    unittest.main()
