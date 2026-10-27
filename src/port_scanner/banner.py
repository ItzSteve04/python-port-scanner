"""Receive-only, size-limited banner collection with terminal-safe text."""

import socket

from .models import BannerResult


def safe_text(text: str) -> str:
    """Escape controls, escape sequences, newlines, and Unicode format controls.

    Backslashes are doubled so literal escape-like strings remain distinguishable.
    Non-ASCII printable text is preserved. This also prevents multiline output.
    """
    result: list[str] = []
    for character in text:
        code = ord(character)
        if character == "\\":
            result.append("\\\\")
        elif character.isprintable():
            result.append(character)
        elif code < 256:
            result.append(f"\\x{code:02x}")
        elif code <= 0xFFFF:
            result.append(f"\\u{code:04x}")
        else:
            result.append(f"\\U{code:08x}")
    return "".join(result)


def grab_banner(connection: socket.socket, timeout: float, max_bytes: int) -> BannerResult:
    """Perform one receive on the existing connection without sending probes.

    TLS and protocols waiting for a client request commonly yield no banner.
    A failed banner read never changes the already-observed open port state.
    """
    try:
        connection.settimeout(timeout)
        data = connection.recv(max_bytes)
    except TimeoutError:
        return BannerResult("timeout")
    except OSError:
        return BannerResult("error")
    if not data:
        return BannerResult("empty")
    return BannerResult(
        "received",
        safe_text(data.decode("utf-8", errors="replace")),
        len(data),
        len(data) == max_bytes,
    )
