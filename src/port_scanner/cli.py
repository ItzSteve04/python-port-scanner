"""Readable argparse interface with explicit authorization and graceful SIGINT."""

import argparse
import logging
import signal
import sys
import time
from collections.abc import Sequence
from dataclasses import replace
from pathlib import Path
from typing import TextIO

from . import __version__
from .banner import safe_text
from .exporters import export_csv, export_json
from .models import PortState, ScanConfig, ScanProgress, ScanReport
from .ports import COMMON_PORTS, parse_ports
from .scanner import AuthorizationError, TCPScanner
from .targets import TargetError


class ProgressDisplay:
    """Throttle terminal updates; redirected output receives one final line."""

    def __init__(self, stream: TextIO, enabled: bool = True) -> None:
        self.stream = stream
        self.enabled = enabled
        self._last = 0.0
        self._active = False

    def update(self, progress: ScanProgress) -> None:
        """Render at most ten times a second on interactive terminals."""
        if not self.enabled or not self.stream.isatty():
            return
        now = time.monotonic()
        if now - self._last < 0.1 and progress.completed != progress.total:
            return
        self._last = now
        self._active = True
        percent = 100 * progress.completed / progress.total
        self.stream.write(
            f"\rProgress: {progress.completed}/{progress.total} ({percent:5.1f}%)"
            f" | open: {progress.open_count}   "
        )
        self.stream.flush()

    def finish(self, report: ScanReport) -> None:
        """Terminate the progress line even when the scan was interrupted."""
        if not self.enabled:
            return
        prefix = "\r" if self._active else ""
        self.stream.write(
            f"{prefix}Progress: {len(report.results)}/{len(report.config.ports)}"
            f" | open: {report.counts['open']} | unscanned: {len(report.unscanned_ports)}   \n"
        )
        self.stream.flush()


def build_parser() -> argparse.ArgumentParser:
    """Describe every supported option and its bounded resource settings."""
    parser = argparse.ArgumentParser(
        prog="port-scanner",
        description="Python Port Scanner: rate-limited TCP connect scans for authorized testing.",
        epilog="Only scan systems you own or have explicit permission to test.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument("target", help="One IP address or hostname; no URL or CIDR.")
    parser.add_argument(
        "-p",
        "--ports",
        default=None,
        metavar="PORTS",
        help=f"Comma-separated ports/ranges; omitted = {len(COMMON_PORTS)} common ports.",
    )
    parser.add_argument(
        "-t", "--timeout", type=float, default=1.0, help="Connect timeout in seconds (0.05-10)."
    )
    parser.add_argument(
        "-w", "--workers", type=int, default=32, help="Maximum concurrent workers (1-128)."
    )
    parser.add_argument(
        "--rate",
        type=float,
        default=50.0,
        help="Global connection permits per second (1-200), without token bursts.",
    )
    parser.add_argument(
        "--family",
        choices=("auto", "ipv4", "ipv6"),
        default="auto",
        help="Address family; auto prefers IPv4 and scans one resolved address.",
    )
    parser.add_argument(
        "--banner", action="store_true", help="Receive a passive banner; sends no data."
    )
    parser.add_argument(
        "--banner-timeout",
        type=float,
        default=0.5,
        help="Banner receive timeout in seconds (0.05-5).",
    )
    parser.add_argument(
        "--banner-bytes", type=int, default=1024, help="Maximum bytes in one banner read (1-4096)."
    )
    parser.add_argument(
        "--authorized",
        action="store_true",
        help="Assert that you own or have explicit permission to scan the target.",
    )
    parser.add_argument("--json", type=Path, dest="json_path", metavar="PATH", help="Export JSON.")
    parser.add_argument("--csv", type=Path, dest="csv_path", metavar="PATH", help="Export CSV.")
    parser.add_argument(
        "--show-all", action="store_true", help="Show all observed states in the table."
    )
    parser.add_argument(
        "--no-progress", action="store_true", help="Disable progress output on stderr."
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable diagnostic logging.")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser


def _confirm_authorization(target: str) -> bool:
    if not sys.stdin.isatty():
        print(
            "Authorization required: use --authorized only with ownership or permission.",
            file=sys.stderr,
        )
        return False
    print(f"Target: {target}\nOnly proceed if you own or have explicit permission to test it.")
    try:
        return input("Type 'I AM AUTHORIZED' to confirm: ").strip() == "I AM AUTHORIZED"
    except EOFError:
        return False


def _validate_export_paths(parser: argparse.ArgumentParser, paths: list[Path]) -> None:
    resolved: set[Path] = set()
    for path in paths:
        normalized = path.resolve()
        if normalized in resolved:
            parser.error("JSON and CSV outputs must use different file paths.")
        resolved.add(normalized)
        if path.is_dir() or not path.parent.is_dir():
            parser.error(f"Output needs an existing parent directory and a filename: {path}")


def print_report(report: ScanReport, show_all: bool = False) -> None:
    """Print stable plain text without trusting remote terminal control data."""
    print(f"\nPython Port Scanner {__version__}")
    print(f"Target: {report.config.target} -> {report.target.ip} ({report.target.family_name})")
    if len(report.target.addresses) > 1:
        print(
            f"Resolved {len(report.target.addresses)} addresses; scanned only {report.target.ip}."
        )
    print(f"TCP connect | workers: {report.config.workers} | rate limit: {report.config.rate:g}/s")
    print(f"{'PORT':<11} {'STATE':<12} {'SERVICE HINT':<26} {'CONNECT':>10}")
    print("-" * 64)
    visible = [result for result in report.results if show_all or result.state == PortState.OPEN]
    for result in visible:
        print(
            f"{str(result.port) + '/tcp':<11} {result.state.value:<12} "
            f"{safe_text(result.service):<26} {result.connect_ms:>7.3f} ms"
        )
        if result.banner:
            note = " (byte limit reached)" if result.banner.at_limit else ""
            # Banner text was already escaped at the untrusted-data boundary.
            print(f"  banner [{result.banner.status}]{note}: {result.banner.text[:240]}")
        if result.error and show_all:
            print(f"  detail: {result.error}")
    if not visible:
        print("No open TCP ports observed." if not show_all else "No completed observations.")
    counts = report.counts
    status = "INTERRUPTED" if report.interrupted else "COMPLETE"
    print(
        f"\n{status}: {len(report.results)}/{len(report.config.ports)} ports in "
        f"{report.duration_seconds:.2f}s | open={counts['open']} closed={counts['closed']} "
        f"timed_out={counts['timed_out']} unreachable={counts['unreachable']} "
        f"errors={counts['error']} unscanned={len(report.unscanned_ports)}"
    )
    print("Service names are port-based hints; they do not verify software or vulnerabilities.")


def main(argv: Sequence[str] | None = None) -> int:
    """Run the CLI; return 0, 1 (operational error), 2 (usage/auth), or 130 (SIGINT)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )
    try:
        config = ScanConfig(
            target=args.target,
            ports=parse_ports(args.ports) if args.ports is not None else COMMON_PORTS,
            timeout=args.timeout,
            workers=args.workers,
            rate=args.rate,
            banner=args.banner,
            banner_timeout=args.banner_timeout,
            banner_bytes=args.banner_bytes,
            family=args.family,
            authorized=args.authorized,
        )
    except (ValueError, TypeError) as exc:
        parser.error(str(exc))
    _validate_export_paths(parser, [p for p in (args.json_path, args.csv_path) if p is not None])
    try:
        if not config.authorized:
            if not _confirm_authorization(config.target):
                print("Scan cancelled: authorization was not confirmed.", file=sys.stderr)
                return 2
            config = replace(config, authorized=True)
        scanner = TCPScanner(config)
        progress = ProgressDisplay(sys.stderr, not args.no_progress)
        print(f"Authorized target: {config.target}; resolving and starting TCP scan...", flush=True)
        previous_handler = signal.getsignal(signal.SIGINT)
        # A signal handler lets the scanner drain bounded in-flight tasks and export a report.
        signal.signal(signal.SIGINT, lambda _signum, _frame: scanner.cancel())
        try:
            report = scanner.scan(progress.update)
        finally:
            signal.signal(signal.SIGINT, previous_handler)
        progress.finish(report)
        print_report(report, args.show_all)
        failed_export = False
        for path, exporter, label in (
            (args.json_path, export_json, "JSON"),
            (args.csv_path, export_csv, "CSV"),
        ):
            if path is not None:
                try:
                    exporter(report, path)
                    print(f"Saved {label}: {safe_text(str(path))}")
                except (OSError, ValueError) as exc:
                    print(f"Cannot export {label}: {safe_text(str(exc))}", file=sys.stderr)
                    failed_export = True
        if report.interrupted:
            return 130
        return 1 if failed_export or report.counts["error"] else 0
    except (TargetError, AuthorizationError, OSError) as exc:
        print(f"Scan failed: {safe_text(str(exc))}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("\nScan cancelled before a report was available.", file=sys.stderr)
        return 130
