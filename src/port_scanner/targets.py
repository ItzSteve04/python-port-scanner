"""Validate one target and pin its resolution for the entire scan."""

import ipaddress
import re
import socket
from dataclasses import dataclass
from typing import Literal, cast

AddressFamily = Literal["auto", "ipv4", "ipv6"]


class TargetError(ValueError):
    """The target is invalid, disallowed, or cannot be resolved."""


def normalize_target(target: str) -> str:
    """Accept one IP literal or DNS hostname; reject URLs, CIDRs, and lists."""
    if not target or target != target.strip() or any(c.isspace() for c in target):
        raise TargetError("Provide one IP address or hostname without whitespace.")
    if len(target) > 254 or any(c in target for c in "/\\[]@\x00"):
        raise TargetError("Use a bare IP address or hostname, without URL, CIDR, or brackets.")
    try:
        address = ipaddress.ip_address(target)
    except ValueError:
        if ":" in target or "%" in target or re.fullmatch(r"[0-9.]+", target):
            raise TargetError("Invalid IP address.") from None
        try:
            bare_hostname = target[:-1] if target.endswith(".") else target
            hostname = bare_hostname.encode("idna").decode("ascii").lower()
        except UnicodeError as exc:
            raise TargetError("Invalid internationalized hostname.") from exc
        labels = hostname.split(".")
        if len(hostname) > 253 or any(
            not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels
        ):
            raise TargetError("Invalid hostname.") from None
        return hostname + ("." if target.endswith(".") else "")
    _check_unicast(address)
    return str(address)


def _check_unicast(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> None:
    """Reject unspecified, multicast, and the IPv4 limited broadcast address."""
    effective = address.ipv4_mapped if isinstance(address, ipaddress.IPv6Address) else None
    if effective is not None:
        address = effective
    if address.is_unspecified or address.is_multicast or str(address) == "255.255.255.255":
        raise TargetError("The target must be a unicast host address.")


@dataclass(frozen=True, slots=True)
class ResolvedTarget:
    """An immutable socket endpoint; workers never re-resolve its hostname."""

    hostname: str
    ip: str
    family: int
    addresses: tuple[str, ...]
    flowinfo: int = 0
    scope_id: int = 0

    @property
    def family_name(self) -> str:
        """Return the printable IP family."""
        return "ipv6" if self.family == socket.AF_INET6 else "ipv4"

    def endpoint(self, port: int) -> tuple[str, int] | tuple[str, int, int, int]:
        """Construct an IPv4 or scoped IPv6 socket address."""
        if self.family == socket.AF_INET6:
            return (self.ip, port, self.flowinfo, self.scope_id)
        return (self.ip, port)


def resolve_target(target: str, family: AddressFamily = "auto") -> ResolvedTarget:
    """Resolve once, prefer IPv4 in auto mode, and scan exactly one address.

    DNS uses the operating system resolver and its own timeout policy.
    Socket connect timeouts do not bound name resolution.
    """
    hostname = normalize_target(target)
    requested = {"auto": socket.AF_UNSPEC, "ipv4": socket.AF_INET, "ipv6": socket.AF_INET6}
    if family not in requested:
        raise TargetError("Address family must be auto, ipv4, or ipv6.")
    try:
        answers = socket.getaddrinfo(
            hostname, 0, requested[family], socket.SOCK_STREAM, socket.IPPROTO_TCP
        )
    except (OSError, UnicodeError) as exc:
        raise TargetError(f"Cannot resolve {hostname!r}: {exc}") from exc
    candidates = [a for a in answers if a[0] in (socket.AF_INET, socket.AF_INET6)]
    if not candidates:
        raise TargetError(f"No usable TCP address for {hostname!r}.")
    if family == "auto":
        candidates.sort(key=lambda a: a[0] != socket.AF_INET)
    for answer in candidates:
        _check_unicast(ipaddress.ip_address(answer[4][0]))
    selected = candidates[0]
    sockaddr = selected[4]
    ipv6_sockaddr = cast(tuple[str, int, int, int], sockaddr)
    return ResolvedTarget(
        hostname=hostname,
        ip=str(sockaddr[0]),
        family=selected[0],
        addresses=tuple(dict.fromkeys(str(a[4][0]) for a in candidates)),
        flowinfo=ipv6_sockaddr[2] if selected[0] == socket.AF_INET6 else 0,
        scope_id=ipv6_sockaddr[3] if selected[0] == socket.AF_INET6 else 0,
    )
