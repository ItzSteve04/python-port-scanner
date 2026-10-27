"""Curated TCP hints with a maintained operating-system services fallback."""

import json
import socket
from dataclasses import dataclass
from importlib.resources import files


@dataclass(frozen=True, slots=True)
class ServiceHint:
    """A convention inferred from a port number, not a verified protocol."""

    name: str
    source: str


class ServiceRegistry:
    """Load the versioned project mapping once for each scanner instance."""

    def __init__(self) -> None:
        document = json.loads(files("port_scanner").joinpath("data/services.json").read_text())
        self._services: dict[str, str] = document["tcp"]

    def identify(self, port: int) -> ServiceHint:
        """Prefer explicit project hints, then the local TCP services database."""
        if str(port) in self._services:
            return ServiceHint(self._services[str(port)], "curated")
        try:
            return ServiceHint(socket.getservbyport(port, "tcp"), "system")
        except OSError:
            return ServiceHint("unknown", "unknown")
