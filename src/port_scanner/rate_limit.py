"""A global connection-start limiter shared by every worker."""

import threading
import time


class RateLimiter:
    """Space permits without an accumulated token burst; support cancellation."""

    def __init__(self, connections_per_second: float) -> None:
        self._interval = 1.0 / connections_per_second
        self._next = 0.0
        self._lock = threading.Lock()

    def acquire(self, stop: threading.Event) -> bool:
        """Return false when cancelled before the next connection permit."""
        with self._lock:
            delay = max(0.0, self._next - time.monotonic())
            if stop.wait(delay):
                return False
            self._next = time.monotonic() + self._interval
            return True
