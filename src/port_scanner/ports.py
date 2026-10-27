"""Parse bounded TCP port specifications without network activity."""

import re

COMMON_PORTS: tuple[int, ...] = (
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    111,
    135,
    139,
    143,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8008,
    8080,
    8443,
    9200,
    27017,
)


def parse_ports(specification: str) -> tuple[int, ...]:
    """Return sorted, unique ports from e.g. ``22,80,8000-8010``.

    Only decimal integers from 1 through 65535 are valid. Empty items and
    descending ranges are rejected rather than silently ignored.
    """
    ports: set[int] = set()
    if len(specification) > 400_000:
        raise ValueError("Port specification is too long.")
    for item in specification.split(","):
        match = re.fullmatch(r"\s*([0-9]{1,5})\s*(?:-\s*([0-9]{1,5})\s*)?", item)
        if not match:
            raise ValueError(f"Invalid port item: {item!r}; use 22,80,8000-8010.")
        start = int(match[1])
        end = int(match[2]) if match[2] is not None else start
        if not 1 <= start <= end <= 65535:
            raise ValueError("Ports must be in 1-65535 and ranges must be ascending.")
        ports.update(range(start, end + 1))
    return tuple(sorted(ports))
