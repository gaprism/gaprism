"""Discovery: find the hosts of a domain in Certificate Transparency logs.

The first stage of every scan. The engine turns its result into hosts and queues their checks.
"""

from __future__ import annotations

from typing import cast

from app.checks.base import CheckContext, CheckOutcome, CheckScope
from app.service.discovery.scope import canonicalise_domain
from app.service.discovery.service import DiscoveryMode, run_discovery
from app.service.discovery.sources import build_sources


class DiscoveryCheck:
    """Ask the configured CT sources about the domain and merge their answers."""

    key = "discovery"
    scope: CheckScope = "domain"
    needs: tuple[str, ...] = ()

    def run(self, ctx: CheckContext) -> CheckOutcome:
        scope = canonicalise_domain(ctx.domain)
        result = run_discovery(
            scope,
            build_sources(ctx.config, ctx.http),
            mode=cast(DiscoveryMode, ctx.config["CT_MODE"]),
            max_hosts=int(ctx.config["MAX_HOSTS_PER_RUN"]),
            budget_seconds=float(ctx.config["DISCOVERY_BUDGET_SECONDS"]),
        )
        data = result.to_data()
        answered = sorted(o.source for o in result.outcomes if o.status == "ok")
        if answered:
            return CheckOutcome("ok", data=data, source="ct:" + "+".join(answered))
        every_unavailable = all(o.status == "unavailable" for o in result.outcomes)
        return CheckOutcome(
            "unavailable" if every_unavailable else "error",
            reason_code="all_sources_failed",
            data=data,
            source="ct",
        )
