"""Certificate Transparency discovery sources (ctlogs.dev, CertSpotter, crt.sh)."""

from __future__ import annotations

import time
from collections.abc import Callable, Mapping
from typing import Any

import httpx

from app.service.discovery.sources.base import (
    DiscoveredName,
    DiscoverySource,
    FetchPolicy,
    SourceOutcome,
)
from app.service.discovery.sources.certspotter import CertSpotterSource
from app.service.discovery.sources.crtsh import CrtShSource
from app.service.discovery.sources.ctlogs import CtlogsSource

SOURCE_KEYS = ("ctlogs", "certspotter", "crtsh")


def build_sources(
    config: Mapping[str, Any],
    client: httpx.Client,
    sleep: Callable[[float], None] = time.sleep,
) -> list[DiscoverySource]:
    """Build the sources named in ``CT_SOURCES``, in that order, with their keys and limits."""
    max_pages = int(config["MAX_DISCOVERY_PAGES"])
    builders: dict[str, Callable[[], DiscoverySource]] = {
        "ctlogs": lambda: CtlogsSource(
            client,
            api_key=str(config.get("CTLOGS_API_KEY") or ""),
            max_pages=max_pages,
            policy=FetchPolicy(attempts=2, sleep=sleep),
        ),
        "certspotter": lambda: CertSpotterSource(
            client,
            token=str(config.get("CERTSPOTTER_TOKEN") or ""),
            max_pages=max_pages,
            policy=FetchPolicy(attempts=2, sleep=sleep),
        ),
        "crtsh": lambda: CrtShSource(client, policy=FetchPolicy(attempts=3, sleep=sleep)),
    }
    unknown = [key for key in config["CT_SOURCES"] if key not in builders]
    if unknown:
        raise ValueError(f"Unknown CT source(s): {', '.join(unknown)}")
    return [builders[key]() for key in config["CT_SOURCES"]]


__all__ = [
    "SOURCE_KEYS",
    "CertSpotterSource",
    "CrtShSource",
    "CtlogsSource",
    "DiscoveredName",
    "DiscoverySource",
    "SourceOutcome",
    "build_sources",
]
