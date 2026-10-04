"""Politeness towards external providers: one rate limiter per provider, shared by all threads.

A limiter hands out time slots, at most ``per_second`` per second. A thread reserves its slot under
a lock and then sleeps outside it, so waiting threads never block each other from reserving.
``KeyedLocks`` lets threads that want the same thing (the same IP address, say) take turns, so the
first one asks the provider and the others find its answer in the cache.
"""

from __future__ import annotations

import threading
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager


class RateLimiter:
    """At most ``per_second`` calls per second, across threads (callers wait for their slot)."""

    def __init__(
        self,
        per_second: float,
        *,
        clock: Callable[[], float] = time.monotonic,
        sleep: Callable[[float], None] = time.sleep,
    ) -> None:
        if per_second <= 0:
            raise ValueError("The rate must be positive.")
        self.per_second = per_second
        self._interval = 1.0 / per_second
        self._clock = clock
        self._sleep = sleep
        self._next_slot = 0.0
        self._lock = threading.Lock()

    def acquire(self) -> float:
        """Block until a call is allowed; returns how long this caller waited (seconds)."""
        with self._lock:
            now = self._clock()
            slot = max(now, self._next_slot)
            self._next_slot = slot + self._interval
        wait = slot - now
        if wait > 0:
            self._sleep(wait)
        return max(0.0, wait)


class LimiterRegistry:
    """One limiter per provider name; asking again with another rate replaces it."""

    def __init__(self) -> None:
        self._limiters: dict[str, RateLimiter] = {}
        self._lock = threading.Lock()

    def get(self, name: str, per_second: float) -> RateLimiter:
        with self._lock:
            limiter = self._limiters.get(name)
            if limiter is None or limiter.per_second != per_second:
                limiter = self._limiters[name] = RateLimiter(per_second)
            return limiter


LIMITERS = LimiterRegistry()


class KeyedLocks:
    """One lock per key: callers with the same key take turns, callers with other keys do not wait.

    A lock exists only while somebody holds or waits for it, so the table stays small however many
    different keys come by.
    """

    def __init__(self) -> None:
        self._guard = threading.Lock()
        self._locks: dict[str, tuple[threading.Lock, int]] = {}

    def __len__(self) -> int:
        """How many keys are held or waited for right now."""
        with self._guard:
            return len(self._locks)

    @contextmanager
    def hold(self, key: str) -> Iterator[None]:
        with self._guard:
            lock, users = self._locks.get(key, (threading.Lock(), 0))
            self._locks[key] = (lock, users + 1)
        try:
            with lock:
                yield
        finally:
            with self._guard:
                lock, users = self._locks[key]
                if users <= 1:
                    del self._locks[key]
                else:
                    self._locks[key] = (lock, users - 1)
