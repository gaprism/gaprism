"""The shared rate limiter that keeps us polite towards external providers."""

from __future__ import annotations

import threading
import time

import pytest

from app.service.ratelimit import LIMITERS, KeyedLocks, LimiterRegistry, RateLimiter


class FakeTime:
    """A clock that only moves when the limiter sleeps (or the test advances it)."""

    def __init__(self) -> None:
        self.now = 100.0
        self.sleeps: list[float] = []
        self._lock = threading.Lock()

    def clock(self) -> float:
        return self.now

    def sleep(self, seconds: float) -> None:
        with self._lock:
            self.sleeps.append(seconds)


def limiter(per_second: float, fake: FakeTime) -> RateLimiter:
    return RateLimiter(per_second, clock=fake.clock, sleep=fake.sleep)


def test_the_first_call_is_free_and_the_next_ones_queue_up() -> None:
    fake = FakeTime()
    lim = limiter(2.0, fake)  # one slot every 0.5 s

    assert lim.acquire() == 0.0
    assert lim.acquire() == pytest.approx(0.5)
    assert lim.acquire() == pytest.approx(1.0)  # still no time passed: the third waits for slot 3
    assert fake.sleeps == [pytest.approx(0.5), pytest.approx(1.0)]


def test_time_passing_frees_the_slots() -> None:
    fake = FakeTime()
    lim = limiter(1.0, fake)
    lim.acquire()
    fake.now += 5.0  # long after the next slot
    assert lim.acquire() == 0.0
    assert fake.sleeps == []


def test_a_rate_must_be_positive() -> None:
    for bad in (0.0, -1.0):
        with pytest.raises(ValueError, match="positive"):
            RateLimiter(bad)


def test_concurrent_callers_get_distinct_slots() -> None:
    fake = FakeTime()
    lim = limiter(4.0, fake)  # 0.25 s apart
    barrier = threading.Barrier(8)
    waits: list[float] = []
    guard = threading.Lock()

    def worker() -> None:
        barrier.wait()
        waited = lim.acquire()
        with guard:
            waits.append(waited)

    threads = [threading.Thread(target=worker) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert sorted(waits) == pytest.approx([i * 0.25 for i in range(8)])  # nobody shared a slot


def test_the_real_clock_really_waits() -> None:
    lim = RateLimiter(100.0)  # 10 ms apart
    started = time.monotonic()
    for _ in range(4):
        lim.acquire()
    assert time.monotonic() - started >= 0.025  # three intervals of 10 ms, with some slack


def test_the_registry_shares_one_limiter_per_provider_and_rate() -> None:
    registry = LimiterRegistry()
    first = registry.get("shodan", 1.0)
    assert registry.get("shodan", 1.0) is first
    assert registry.get("internetdb", 1.0) is not first
    replaced = registry.get("shodan", 2.0)  # the configuration changed
    assert replaced is not first and replaced.per_second == 2.0
    assert registry.get("shodan", 2.0) is replaced


def test_the_process_wide_registry_exists() -> None:
    assert LIMITERS.get("test-provider", 5.0) is LIMITERS.get("test-provider", 5.0)


# ------------------------------------------------------------------------------ KeyedLocks


def test_callers_with_the_same_key_take_turns() -> None:
    locks = KeyedLocks()
    inside = 0
    most_inside = 0
    guard = threading.Lock()
    barrier = threading.Barrier(6)

    def worker() -> None:
        nonlocal inside, most_inside
        barrier.wait()
        with locks.hold("93.184.216.34"):
            with guard:
                inside += 1
                most_inside = max(most_inside, inside)
            time.sleep(0.01)
            with guard:
                inside -= 1

    threads = [threading.Thread(target=worker) for _ in range(6)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)

    assert most_inside == 1  # never two at once
    assert len(locks) == 0  # and nothing is left behind


def test_callers_with_other_keys_do_not_wait_for_each_other() -> None:
    locks = KeyedLocks()
    both_inside = threading.Barrier(2, timeout=5)  # only passes if both are inside at once
    errors: list[BaseException] = []

    def worker(key: str) -> None:
        try:
            with locks.hold(key):
                both_inside.wait()
        except BaseException as exc:
            errors.append(exc)

    threads = [threading.Thread(target=worker, args=(key,)) for key in ("a", "b")]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=10)
    assert errors == [] and len(locks) == 0


def test_a_lock_is_released_when_the_body_fails() -> None:
    locks = KeyedLocks()
    with pytest.raises(RuntimeError), locks.hold("key"):
        raise RuntimeError("boom")
    assert len(locks) == 0
    with locks.hold("key"):  # not stuck
        assert len(locks) == 1
