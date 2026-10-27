"""Atomic JSON and CSV exports; interrupted scans retain their metadata."""

import csv
import json
import os
import tempfile
from collections.abc import Callable
from pathlib import Path
from typing import IO

from .models import ScanReport

CSV_FIELDS = (
    "target",
    "address",
    "family",
    "scope_id",
    "started_at",
    "finished_at",
    "interrupted",
    "requested",
    "completed",
    "unscanned",
    "port",
    "state",
    "service",
    "service_source",
    "connect_ms",
    "banner_status",
    "banner",
    "banner_bytes",
    "banner_at_limit",
    "error",
)


def spreadsheet_safe(value: str) -> str:
    """Neutralize spreadsheet formulas, including leading whitespace tricks."""
    if value.lstrip().startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def _atomic_write(path: Path, writer: Callable[[IO[str]], None]) -> None:
    """Replace one file atomically after a successful write in the same directory."""
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            newline="",
            dir=path.parent,
            prefix=f".{path.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            writer(stream.file)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)


def export_json(report: ScanReport, path: Path) -> None:
    """Write schema 1.0 with all outcomes, summary, config, and unscanned ports."""

    def write(stream: IO[str]) -> None:
        json.dump(report.to_dict(), stream, indent=2, ensure_ascii=True, allow_nan=False)
        stream.write("\n")

    _atomic_write(Path(path), write)


def export_csv(report: ScanReport, path: Path) -> None:
    """Write all completed observations; metadata-only row if none completed.

    CSV cells are formula-safe. JSON preserves the exact escaped banner text.
    """

    def write(stream: IO[str]) -> None:
        writer = csv.DictWriter(stream, fieldnames=CSV_FIELDS)
        writer.writeheader()
        metadata: dict[str, str | int | float | bool] = {
            "target": report.config.target,
            "address": report.target.ip,
            "family": report.target.family_name,
            "scope_id": report.target.scope_id,
            "started_at": report.started_at.isoformat(),
            "finished_at": report.finished_at.isoformat(),
            "interrupted": report.interrupted,
            "requested": len(report.config.ports),
            "completed": len(report.results),
            "unscanned": len(report.unscanned_ports),
        }
        rows: list[dict[str, str | int | float | bool]] = []
        for result in report.results:
            rows.append(
                {
                    **metadata,
                    "port": result.port,
                    "state": result.state.value,
                    "service": result.service,
                    "service_source": result.service_source,
                    "connect_ms": result.connect_ms,
                    "banner_status": result.banner.status if result.banner else "disabled",
                    "banner": result.banner.text if result.banner else "",
                    "banner_bytes": result.banner.bytes_received if result.banner else 0,
                    "banner_at_limit": result.banner.at_limit if result.banner else False,
                    "error": result.error or "",
                }
            )
        for row in rows or [metadata]:
            writer.writerow(
                {k: spreadsheet_safe(v) if isinstance(v, str) else v for k, v in row.items()}
            )

    _atomic_write(Path(path), write)
