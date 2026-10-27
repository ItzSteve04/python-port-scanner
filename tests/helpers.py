"""Loopback-only fixtures and deterministic report data."""

import socket
import socketserver
import threading
from contextlib import contextmanager, suppress
from datetime import UTC, datetime

from port_scanner.models import BannerResult, PortResult, PortState, ScanConfig, ScanReport
from port_scanner.targets import ResolvedTarget


class LocalServer(socketserver.ThreadingTCPServer):
    """A loopback server whose handlers cannot outlive the fixture."""

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True


@contextmanager
def local_server(payload=b"SSH-2.0-LocalTest\r\n", family=socket.AF_INET):
    """Start an ephemeral IPv4 or IPv6 service; never bind a public interface."""
    release = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            if payload is not None:
                with suppress(OSError):
                    self.request.sendall(payload)
            else:
                release.wait(5)

    class Server(LocalServer):
        address_family = family

    host = "::1" if family == socket.AF_INET6 else "127.0.0.1"
    server = Server((host, 0), Handler)
    thread = threading.Thread(
        target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
    )
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        release.set()
        server.shutdown()
        server.server_close()
        thread.join(timeout=2)


@contextmanager
def non_listening_port():
    """Reserve a loopback port without accepting connections.

    Depending on the OS and timeout, connecting can be refused or time out.
    Keeping the bound socket alive prevents another server taking the port.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as connection:
        connection.bind(("127.0.0.1", 0))
        yield connection.getsockname()[1]


def sample_report(interrupted=False, results=True):
    """Construct deterministic local-only observations for exporter tests."""
    observations = (
        (
            PortResult(
                22, PortState.OPEN, "ssh", "curated", 0.2, BannerResult("received", "=1+1", 4)
            ),
            PortResult(80, PortState.CLOSED, "http", "curated", 0.3, error="refused"),
        )
        if results
        else ()
    )
    return ScanReport(
        ScanConfig("127.0.0.1", ports=(22, 80, 443), authorized=True),
        ResolvedTarget("127.0.0.1", "127.0.0.1", socket.AF_INET, ("127.0.0.1",)),
        datetime(2026, 1, 1, tzinfo=UTC),
        datetime(2026, 1, 1, 0, 0, 1, tzinfo=UTC),
        1.0,
        observations,
        interrupted,
    )
