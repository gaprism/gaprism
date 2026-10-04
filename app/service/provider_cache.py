"""The database-backed provider cache (table ``provider_cache``).

Checks receive it as ``CheckContext.cache``; they never touch the database themselves. Each call
runs in its own short transaction on its own session, so a check that is busy talking to a
provider holds no connection and no lock. Only definitive answers (``ok``, ``no_data``) are
stored; errors and quota problems are never remembered.

The cache is an optimisation, so it fails soft: a database problem is logged and behaves like a
miss (``get``) or a skipped write (``put``).
"""

from __future__ import annotations

import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import delete
from sqlalchemy.dialects.postgresql import insert
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session, sessionmaker

from app.checks.base import CachedAnswer
from app.models import ProviderCache
from app.models.base import utc_now
from app.models.provider_cache import CACHE_STATUSES

log = logging.getLogger(__name__)


class DbCacheStore:
    """``CacheStore`` over ``provider_cache``; ``factory`` makes one session per call."""

    def __init__(self, factory: sessionmaker[Session]) -> None:
        self._factory = factory

    def get(self, provider: str, key: str, max_age: timedelta) -> CachedAnswer | None:
        try:
            with self._factory() as session:
                row = session.get(ProviderCache, (provider, key))
                if row is None or row.status not in CACHE_STATUSES:
                    return None
                if row.fetched_at < utc_now() - max_age:
                    return None
                return CachedAnswer(row.status, dict(row.payload), row.fetched_at)
        except SQLAlchemyError:
            log.warning("provider cache read failed for %s", provider, exc_info=True)
            return None

    def put(self, provider: str, key: str, status: str, payload: dict[str, Any]) -> None:
        if status not in CACHE_STATUSES:
            return  # errors and "unavailable" are never cached
        statement = insert(ProviderCache).values(
            provider=provider, cache_key=key, status=status, payload=payload, fetched_at=utc_now()
        )
        statement = statement.on_conflict_do_update(
            index_elements=[ProviderCache.provider, ProviderCache.cache_key],
            set_={
                "status": statement.excluded.status,
                "payload": statement.excluded.payload,
                "fetched_at": statement.excluded.fetched_at,
            },
        )
        try:
            with self._factory() as session, session.begin():
                session.execute(statement)
        except SQLAlchemyError:
            log.warning("provider cache write failed for %s", provider, exc_info=True)

    def purge(self, older_than: timedelta) -> int:
        """Delete entries older than ``older_than``; returns how many went."""
        try:
            with self._factory() as session, session.begin():
                result = session.execute(
                    delete(ProviderCache).where(ProviderCache.fetched_at < utc_now() - older_than)
                )
                return int(getattr(result, "rowcount", 0) or 0)
        except SQLAlchemyError:
            log.warning("provider cache purge failed", exc_info=True)
            return 0
