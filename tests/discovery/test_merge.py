"""Merging CT source results into hosts: scope, wildcards, caps, partial and failed sources."""

from __future__ import annotations

import json
from datetime import UTC, datetime

import httpx
import pytest

from app.config import CT_SOURCE_KEYS
from app.service.discovery import canonicalise_domain, merge_outcomes, normalise_name, run_discovery
from app.service.discovery.sources import SOURCE_KEYS, build_sources
from app.service.discovery.sources.base import DiscoveredName, SourceOutcome

SCOPE = canonicalise_domain("example.com")


def at(day: int) -> datetime:
    return datetime(2026, 1, day, tzinfo=UTC)


def outcome(source: str, *names: str | DiscoveredName, status: str = "ok") -> SourceOutcome:
    items = tuple(DiscoveredName(n) if isinstance(n, str) else n for n in names)
    return SourceOutcome(source, status, None if status == "ok" else "http_500", items)  # type: ignore[arg-type]


def test_union_merges_duplicates_and_keeps_the_widest_time_range_and_all_sources() -> None:
    result = merge_outcomes(
        SCOPE,
        [
            outcome("ctlogs", DiscoveredName("api.example.com", at(5), at(9))),
            outcome("crtsh", DiscoveredName("API.example.com.", at(2), at(7)), "www.example.com"),
        ],
        max_hosts=50,
    )
    api = next(host for host in result.hosts if host.hostname == "api.example.com")
    assert (api.first_seen, api.last_seen, api.sources) == (at(2), at(9), ("crtsh", "ctlogs"))
    assert sorted(host.hostname for host in result.hosts) == ["api.example.com", "www.example.com"]


def test_wildcards_are_patterns_never_hosts() -> None:
    result = merge_outcomes(
        SCOPE,
        [outcome("crtsh", "*.example.com", "*.dev.example.com", "a.example.com")],
        max_hosts=50,
    )
    assert result.wildcard_patterns == ("*.dev.example.com", "*.example.com")
    assert [host.hostname for host in result.hosts] == ["a.example.com"]


def test_names_outside_the_assessed_domain_are_counted_and_excluded() -> None:
    result = merge_outcomes(
        SCOPE,
        [
            outcome(
                "certspotter",
                "example.net",
                "notexample.com",
                "example.com.evil.test",
                "*.other.org",
                "ok.example.com",
            )
        ],
        max_hosts=50,
    )
    assert [host.hostname for host in result.hosts] == ["ok.example.com"]
    assert result.out_of_scope == 4 and result.wildcard_patterns == ()


def test_invalid_names_are_counted_not_scanned() -> None:
    result = merge_outcomes(
        SCOPE,
        [
            outcome(
                "crtsh",
                "bad_label.example.com",
                "has space.example.com",
                "-x.example.com",
                "single",
                "good.example.com",
            )
        ],
        max_hosts=50,
    )
    assert [host.hostname for host in result.hosts] == ["good.example.com"]
    assert result.invalid_names == 4


def test_unicode_names_become_punycode() -> None:
    assert normalise_name("MÜNCHEN.de") == ("xn--mnchen-3ya.de", False)
    assert normalise_name("*.münchen.de") == ("xn--mnchen-3ya.de", True)
    assert normalise_name("a" * 64 + ".com") is None


def test_the_host_cap_keeps_the_apex_then_the_most_recently_seen() -> None:
    names = [DiscoveredName(f"h{i}.example.com", at(1), at(i)) for i in range(1, 9)]
    names.append(DiscoveredName("example.com", at(1), at(1)))  # oldest, but the apex
    names.append(DiscoveredName("undated.example.com"))
    result = merge_outcomes(SCOPE, [outcome("ctlogs", *names)], max_hosts=4)
    assert [host.hostname for host in result.hosts] == [
        "example.com",
        "h8.example.com",
        "h7.example.com",
        "h6.example.com",
    ]
    assert result.dropped_by_cap == 6


def test_partial_names_from_a_failed_source_still_count_and_failures_stay_visible() -> None:
    result = merge_outcomes(
        SCOPE,
        [
            outcome("ctlogs", "a.example.com", status="error"),
            outcome("crtsh", status="unavailable"),
        ],
        max_hosts=50,
    )
    assert [host.hostname for host in result.hosts] == ["a.example.com"]
    assert result.sources_ok == 0
    assert [o["status"] for o in result.to_data()["sources"]] == ["error", "unavailable"]


def test_result_data_is_json_serialisable_and_counts_add_up() -> None:
    result = merge_outcomes(
        SCOPE,
        [
            outcome(
                "ctlogs", DiscoveredName("a.example.com", at(1), at(2)), "*.example.com", "x.org"
            )
        ],
        max_hosts=50,
    )
    data = json.loads(json.dumps(result.to_data()))
    assert data["counts"] == {
        "names_seen": 3,
        "hosts": 1,
        "out_of_scope": 1,
        "invalid": 0,
        "dropped_by_cap": 0,
    }
    assert data["hosts"][0]["last_seen"] == at(2).isoformat()


class FakeSource:
    def __init__(self, key: str, result: SourceOutcome) -> None:
        self.key = key
        self.result = result
        self.calls: list[str] = []

    def fetch(self, domain: str) -> SourceOutcome:
        self.calls.append(domain)
        return self.result


def test_union_asks_every_source_even_after_a_failure() -> None:
    sources = [
        FakeSource("a", outcome("a", status="error")),
        FakeSource("b", outcome("b", "x.example.com")),
        FakeSource("c", outcome("c", "y.example.com")),
    ]
    result = run_discovery(SCOPE, sources, mode="union")
    assert [s.calls for s in sources] == [["example.com"]] * 3
    assert sorted(host.hostname for host in result.hosts) == ["x.example.com", "y.example.com"]


def test_first_mode_stops_after_the_first_source_that_answers() -> None:
    sources = [
        FakeSource("a", outcome("a", status="unavailable")),
        FakeSource("b", outcome("b", "x.example.com")),
        FakeSource("c", outcome("c", "y.example.com")),
    ]
    result = run_discovery(SCOPE, sources, mode="first")
    assert [len(s.calls) for s in sources] == [1, 1, 0]
    assert [host.hostname for host in result.hosts] == ["x.example.com"]


def test_sources_are_built_from_config_in_the_configured_order() -> None:
    config = {
        "CT_SOURCES": ["crtsh", "ctlogs"],
        "MAX_DISCOVERY_PAGES": 7,
        "CTLOGS_API_KEY": "k",
        "CERTSPOTTER_TOKEN": "",
    }
    with httpx.Client() as client:
        built = build_sources(config, client)
        assert [source.key for source in built] == ["crtsh", "ctlogs"]
        with pytest.raises(ValueError, match="Unknown CT source"):
            build_sources({**config, "CT_SOURCES": ["nope"]}, client)


def test_source_names_are_the_same_in_config_validation_and_the_factory() -> None:
    assert SOURCE_KEYS == CT_SOURCE_KEYS
