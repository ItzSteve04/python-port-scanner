"""Typed configuration, observations, and a versioned export model."""

import math
from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

from .ports import COMMON_PORTS
from .targets import AddressFamily, ResolvedTarget, normalize_target


class PortState(StrEnum):
    """Observed TCP outcomes; a timeout is not proof of filtering."""

    OPEN = "open"
    CLOSED = "closed"
    TIMED_OUT = "timed_out"
    UNREACHABLE = "unreachable"
    ERROR = "error"


@dataclass(frozen=True, slots=True)
class ScanConfig:
    """A single-target scan with conservative, enforced resource limits."""

    target: str
    ports: tuple[int, ...] = COMMON_PORTS
    timeout: float = 1.0
    workers: int = 32
    rate: float = 50.0
    banner: bool = False
    banner_timeout: float = 0.5
    banner_bytes: int = 1024
    family: AddressFamily = "auto"
    authorized: bool = False

    def __post_init__(self) -> None:
        object.__setattr__(self, "target", normalize_target(self.target))
        if (
            not self.ports
            or len(self.ports) > 65535
            or any(type(p) is not int or not 1 <= p <= 65535 for p in self.ports)
        ):
            raise ValueError("Provide TCP ports between 1 and 65535.")
        object.__setattr__(self, "ports", tuple(sorted(set(self.ports))))
        for name, value, low, high in (
            ("timeout", self.timeout, 0.05, 10.0),
            ("rate", self.rate, 1.0, 200.0),
            ("banner_timeout", self.banner_timeout, 0.05, 5.0),
        ):
            if isinstance(value, bool) or not math.isfinite(value) or not low <= value <= high:
                raise ValueError(f"{name} must be finite and between {low} and {high}.")
        if type(self.workers) is not int or not 1 <= self.workers <= 128:
            raise ValueError("workers must be between 1 and 128.")
        if type(self.banner_bytes) is not int or not 1 <= self.banner_bytes <= 4096:
            raise ValueError("banner_bytes must be between 1 and 4096.")
        if self.family not in ("auto", "ipv4", "ipv6"):
            raise ValueError("family must be auto, ipv4, or ipv6.")
        if type(self.authorized) is not bool or type(self.banner) is not bool:
            raise ValueError("authorized and banner must be booleans.")


@dataclass(frozen=True, slots=True)
class BannerResult:
    """A single bounded receive; text has escaped control characters."""

    status: str
    text: str = ""
    bytes_received: int = 0
    at_limit: bool = False


@dataclass(frozen=True, slots=True)
class PortResult:
    """One completed port observation, including guessed service provenance."""

    port: int
    state: PortState
    service: str
    service_source: str
    connect_ms: float
    banner: BannerResult | None = None
    error: str | None = None


@dataclass(frozen=True, slots=True)
class ScanProgress:
    """A main-thread progress update after a completed port."""

    completed: int
    total: int
    open_count: int


@dataclass(frozen=True, slots=True)
class ScanReport:
    """A complete or interrupted scan, suitable for durable JSON export."""

    config: ScanConfig
    target: ResolvedTarget
    started_at: datetime
    finished_at: datetime
    duration_seconds: float
    results: tuple[PortResult, ...]
    interrupted: bool = False

    @property
    def counts(self) -> dict[str, int]:
        """Count every observation, including zero-count states."""
        observed = Counter(result.state.value for result in self.results)
        return {state.value: observed[state.value] for state in PortState}

    @property
    def unscanned_ports(self) -> tuple[int, ...]:
        """Return ports with no completed observation, never label them closed."""
        completed = {result.port for result in self.results}
        return tuple(port for port in self.config.ports if port not in completed)

    def to_dict(self) -> dict[str, Any]:
        """Build the documented schema without omitting failed observations."""
        from . import __version__

        return {
            "schema_version": "1.0",
            "scanner_version": __version__,
            "target": {
                "input": self.config.target,
                "address": self.target.ip,
                "family": self.target.family_name,
                "scope_id": self.target.scope_id,
                "resolved_addresses": list(self.target.addresses),
            },
            "started_at": self.started_at.isoformat(),
            "finished_at": self.finished_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 6),
            "interrupted": self.interrupted,
            "configuration": asdict(self.config),
            "summary": {
                "requested": len(self.config.ports),
                "completed": len(self.results),
                "unscanned": len(self.unscanned_ports),
                **self.counts,
            },
            "unscanned_ports": list(self.unscanned_ports),
            "results": [asdict(result) for result in self.results],
        }
