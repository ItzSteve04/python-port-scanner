"""Bounded concurrent TCP connect scanning with partial-result preservation."""

import errno
import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from concurrent.futures import FIRST_COMPLETED, Future, ThreadPoolExecutor, wait
from datetime import UTC, datetime

from .banner import grab_banner, safe_text
from .models import BannerResult, PortResult, PortState, ScanConfig, ScanProgress, ScanReport
from .rate_limit import RateLimiter
from .services import ServiceRegistry
from .targets import ResolvedTarget, resolve_target

logger = logging.getLogger(__name__)


class AuthorizationError(PermissionError):
    """Authorization must be explicitly asserted before any target resolution."""


def classify_error(code: int) -> PortState:
    """Map POSIX and Winsock error codes without overclaiming firewall state."""
    if code in (errno.ECONNREFUSED, 10061):
        return PortState.CLOSED
    if code in (errno.ETIMEDOUT, errno.EAGAIN, errno.EWOULDBLOCK, 10060, 10035):
        return PortState.TIMED_OUT
    if code in (errno.EHOSTUNREACH, errno.ENETUNREACH, errno.ENETDOWN, 10051, 10064, 10065):
        return PortState.UNREACHABLE
    return PortState.ERROR


def describe_connect_error(code: int) -> str:
    """Describe connect_ex outcomes without passing Winsock codes to strerror.

    A timed socket's connect_ex may return WSAEWOULDBLOCK after its wait
    expires. It is not an explicit connection refusal and remains timed_out.
    """
    winsock_messages = {
        10013: "Permission denied (WSAEACCES).",
        10024: "Too many open sockets (WSAEMFILE).",
        10035: "Connection did not complete within the connect timeout (WSAEWOULDBLOCK).",
        10050: "Network is down (WSAENETDOWN).",
        10051: "Network is unreachable (WSAENETUNREACH).",
        10054: "Connection was reset (WSAECONNRESET).",
        10055: "No buffer space available (WSAENOBUFS).",
        10060: "Connection timed out (WSAETIMEDOUT).",
        10061: "Connection refused (WSAECONNREFUSED).",
        10064: "Host is down (WSAEHOSTDOWN).",
        10065: "Host is unreachable (WSAEHOSTUNREACH).",
    }
    detail = winsock_messages.get(code)
    if detail is None:
        detail = os.strerror(code)
    return safe_text(f"[errno {code}] {detail}")


class TCPScanner:
    """A single-use scanner with at most ``workers`` pending or running tasks.

    Call ``cancel`` from another thread to stop scheduling work. In-flight
    connects and receives finish within their configured socket timeouts.
    """

    def __init__(self, config: ScanConfig) -> None:
        self.config = config
        self._stop = threading.Event()
        self._used = False
        self._run_lock = threading.Lock()
        self._registry = ServiceRegistry()
        self._limiter = RateLimiter(config.rate)

    def cancel(self) -> None:
        """Request cancellation; completed observations remain in the report."""
        self._stop.set()

    def _probe(self, target: ResolvedTarget, port: int) -> PortResult | None:
        if not self._limiter.acquire(self._stop) or self._stop.is_set():
            return None
        service = self._registry.identify(port)
        started = time.perf_counter()
        banner: BannerResult | None = None
        message: str | None = None
        try:
            with socket.socket(target.family, socket.SOCK_STREAM, socket.IPPROTO_TCP) as connection:
                connection.settimeout(self.config.timeout)
                code = connection.connect_ex(target.endpoint(port))
                connect_ms = (time.perf_counter() - started) * 1000
                state = PortState.OPEN if code == 0 else classify_error(code)
                if code:
                    message = describe_connect_error(code)
                elif self.config.banner:
                    banner = (
                        BannerResult("cancelled")
                        if self._stop.is_set()
                        else grab_banner(
                            connection, self.config.banner_timeout, self.config.banner_bytes
                        )
                    )
        except TimeoutError:
            connect_ms = (time.perf_counter() - started) * 1000
            state, message = PortState.TIMED_OUT, "Connection timed out."
        except OSError as exc:
            connect_ms = (time.perf_counter() - started) * 1000
            state, message = classify_error(exc.errno or 0), safe_text(str(exc))
        logger.debug("port=%d state=%s connect_ms=%.3f", port, state, connect_ms)
        return PortResult(
            port, state, service.name, service.source, round(connect_ms, 3), banner, message
        )

    def scan(self, on_progress: Callable[[ScanProgress], None] | None = None) -> ScanReport:
        """Run one authorized scan, preserving completed results on interruption."""
        if not self.config.authorized:
            raise AuthorizationError("Confirm ownership or permission before scanning.")
        with self._run_lock:
            if self._used:
                raise RuntimeError("A TCPScanner instance can only be used once.")
            self._used = True
        target = resolve_target(self.config.target, self.config.family)
        started_at = datetime.now(UTC)
        started = time.perf_counter()
        results: list[PortResult] = []
        open_count = 0
        ports = iter(self.config.ports)
        pending: dict[Future[PortResult | None], int] = {}
        executor = ThreadPoolExecutor(
            max_workers=self.config.workers, thread_name_prefix="tcp-scan"
        )

        def submit_available() -> None:
            while len(pending) < self.config.workers and not self._stop.is_set():
                port = next(ports, None)
                if port is None:
                    break
                pending[executor.submit(self._probe, target, port)] = port

        try:
            submit_available()
            while pending:
                try:
                    if self._stop.is_set():
                        for future in pending:
                            future.cancel()
                    done, _ = wait(pending, timeout=0.1, return_when=FIRST_COMPLETED)
                    for future in done:
                        pending.pop(future)
                        if future.cancelled():
                            continue
                        result = future.result()
                        if result is None:
                            continue
                        results.append(result)
                        open_count += result.state == PortState.OPEN
                        if on_progress:
                            on_progress(
                                ScanProgress(len(results), len(self.config.ports), open_count)
                            )
                    submit_available()
                except KeyboardInterrupt:
                    self.cancel()
                    logger.info("Scan interrupted; collecting in-flight observations.")
        except BaseException:
            self.cancel()
            raise
        finally:
            # Also stop workers if a caller's progress callback raises an exception.
            if pending:
                self.cancel()
            executor.shutdown(wait=True, cancel_futures=True)
        return ScanReport(
            self.config,
            target,
            started_at,
            datetime.now(UTC),
            time.perf_counter() - started,
            tuple(sorted(results, key=lambda result: result.port)),
            self._stop.is_set(),
        )
