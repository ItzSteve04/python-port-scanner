"""Generate real, loopback-only example reports without external dependencies."""

import contextlib
import socket
import socketserver
import subprocess
import sys
import threading
from collections.abc import Iterator
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


@contextlib.contextmanager
def service(payload: bytes | None) -> Iterator[int]:
    """Run one ephemeral localhost greeting or silent TCP service."""
    stop = threading.Event()

    class Handler(socketserver.BaseRequestHandler):
        def handle(self) -> None:
            if payload is not None:
                with contextlib.suppress(OSError):
                    self.request.sendall(payload)
            else:
                stop.wait(5)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        block_on_close = False

    with Server(("127.0.0.1", 0), Handler) as server:
        thread = threading.Thread(
            target=server.serve_forever, kwargs={"poll_interval": 0.02}, daemon=True
        )
        thread.start()
        try:
            yield server.server_address[1]
        finally:
            stop.set()
            server.shutdown()
            thread.join(timeout=2)


def main() -> int:
    """Capture the installed module's output and its JSON/CSV reports."""
    examples = ROOT / "examples"
    examples.mkdir(exist_ok=True)
    with (
        service(b"SSH-2.0-PythonPortScannerDemo\r\n") as greeting,
        service(None) as silent,
        socket.socket(socket.AF_INET, socket.SOCK_STREAM) as reserved,
    ):
        reserved.bind(("127.0.0.1", 0))
        non_listening = reserved.getsockname()[1]
        ports = ",".join(map(str, sorted((greeting, silent, non_listening))))
        arguments = [
            "127.0.0.1",
            "-p",
            ports,
            "--authorized",
            "--banner",
            "--show-all",
            "--banner-timeout",
            "0.15",
            "--workers",
            "4",
            "--rate",
            "20",
            "--json",
            "examples/local-scan.json",
            "--csv",
            "examples/local-scan.csv",
        ]
        command = "$ port-scanner " + " ".join(arguments)
        completed = subprocess.run(
            [sys.executable, "-m", "port_scanner", *arguments],
            cwd=ROOT,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            timeout=10,
            check=False,
        )
    transcript = command + "\n\n" + completed.stdout
    (examples / "terminal-session.txt").write_text(transcript, encoding="utf-8")
    help_output = subprocess.run(
        [sys.executable, "-m", "port_scanner", "--help"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=10,
        check=True,
    )
    (examples / "cli-help.txt").write_text(
        "$ port-scanner --help\n\n" + help_output.stdout, encoding="utf-8"
    )
    print(transcript, end="")
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
