"""The database-backed provider cache: freshness, upserts, only definitive answers, fail-soft."""

from __future__ import annotations

from datetime import timedelta
from typing import Any

import pytest
from sqlalchemy import func, select, update
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, sessionmaker

from app.models import ProviderCache
from app.models.base import utc_now
from app.service.provider_cache import DbCacheStore

DAY = timedelta(hours=24)
IP = "93.184.216.34"


@pytest.fixture
def store(db_session: Session) -> DbCacheStore:
    """A store whose sessions share the test's connection (so everything is rolled back)."""
    factory = sessionmaker(
        bind=db_session.get_bind(),
        expire_on_commit=False,
        join_transaction_mode="create_savepoint",
    )
    return DbCacheStore(factory)


def age(session: Session, provider: str, key: str, by: timedelta) -> None:
    """Make an entry look ``by`` older than it is."""
    session.execute(
        update(ProviderCache)
        .where(ProviderCache.provider == provider, ProviderCache.cache_key == key)
        .values(fetched_at=utc_now() - by)
    )
    session.commit()
    session.expire_all()


def count(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(ProviderCache)) or 0)


def test_an_answer_is_stored_and_read_back(store: DbCacheStore) -> None:
    assert store.get("shodan", IP, DAY) is None

    store.put("shodan", IP, "ok", {"ports": [80, 443], "tags": ["cloud"]})
    answer = store.get("shodan", IP, DAY)

    assert answer is not None
    assert (answer.status, answer.payload) == ("ok", {"ports": [80, 443], "tags": ["cloud"]})
    assert utc_now() - answer.fetched_at < timedelta(minutes=1)
    assert answer.fetched_at.tzinfo is not None


def test_no_data_is_an_answer_too(store: DbCacheStore) -> None:
    store.put("internetdb", IP, "no_data", {})
    answer = store.get("internetdb", IP, DAY)
    assert answer is not None and (answer.status, answer.payload) == ("no_data", {})


@pytest.mark.parametrize("status", ["error", "unavailable", "skipped", "nonsense"])
def test_only_definitive_answers_are_stored(
    store: DbCacheStore, db_session: Session, status: str
) -> None:
    store.put("shodan", IP, status, {"ports": [22]})
    assert store.get("shodan", IP, DAY) is None
    assert count(db_session) == 0


def test_an_entry_expires_after_the_requested_age(store: DbCacheStore, db_session: Session) -> None:
    store.put("shodan", IP, "ok", {"ports": [80]})
    age(db_session, "shodan", IP, timedelta(hours=30))

    assert store.get("shodan", IP, DAY) is None  # older than a day
    assert store.get("shodan", IP, timedelta(hours=48)) is not None  # but not older than two


def test_storing_again_replaces_the_entry_and_refreshes_its_age(
    store: DbCacheStore, db_session: Session
) -> None:
    store.put("shodan", IP, "ok", {"ports": [80]})
    age(db_session, "shodan", IP, timedelta(hours=30))

    store.put("shodan", IP, "ok", {"ports": [443]})

    assert count(db_session) == 1  # an upsert, not a second row
    answer = store.get("shodan", IP, DAY)
    assert answer is not None and answer.payload == {"ports": [443]}


def test_a_later_no_data_replaces_an_earlier_ok_for_the_same_key(store: DbCacheStore) -> None:
    store.put("shodan", IP, "ok", {"ports": [80]})
    store.put("shodan", IP, "no_data", {})
    answer = store.get("shodan", IP, DAY)
    assert answer is not None and (answer.status, answer.payload) == ("no_data", {})


def test_providers_and_keys_are_separate_entries(store: DbCacheStore) -> None:
    store.put("shodan", IP, "ok", {"who": "shodan"})
    store.put("internetdb", IP, "ok", {"who": "internetdb"})
    store.put("shodan", "93.184.216.35", "ok", {"who": "other ip"})

    payloads = {
        ("shodan", IP): "shodan",
        ("internetdb", IP): "internetdb",
        ("shodan", "93.184.216.35"): "other ip",
    }
    for (provider, key), who in payloads.items():
        answer = store.get(provider, key, DAY)
        assert answer is not None and answer.payload == {"who": who}


def test_purge_removes_only_old_entries_and_counts_them(
    store: DbCacheStore, db_session: Session
) -> None:
    for key in ("fresh", "week", "ancient"):
        store.put("shodan", key, "ok", {})
    age(db_session, "shodan", "week", timedelta(days=7))
    age(db_session, "shodan", "ancient", timedelta(days=90))

    assert store.purge(timedelta(days=30)) == 1
    assert {row.cache_key for row in db_session.scalars(select(ProviderCache))} == {"fresh", "week"}
    assert store.purge(timedelta(days=30)) == 0


def test_a_broken_database_makes_the_cache_a_miss_not_a_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken() -> Any:
        raise OperationalError("SELECT 1", {}, Exception("connection lost"))

    store = DbCacheStore(broken)  # type: ignore[arg-type]
    assert store.get("shodan", IP, DAY) is None
    store.put("shodan", IP, "ok", {"ports": [80]})  # does not raise
    assert store.purge(timedelta(days=1)) == 0
    assert "provider cache" in caplog.text  # but it is logged
