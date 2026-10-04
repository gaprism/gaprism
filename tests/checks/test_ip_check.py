"""The IP check: locations and network hints for a host's screened addresses."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import httpx

from app.checks.base import CheckContext, CheckOutcome
from app.checks.ip import MAX_ADDRESSES, MAX_NAME, MAX_PTR_NAMES, IpCheck
from app.service.geo import DatabaseInfo, DbIpProvider, GeoUnavailableError, IpLocation
from tests.geo_helpers import install_databases

CONFIG: dict[str, Any] = {"DATASETS_DIR": "unused", "DNS_TIMEOUT_SECONDS": 5.0}


def dns_outcome(*addresses: str, aliases: tuple[str, ...] = ()) -> CheckOutcome:
    chain = [{"name": "www.example.com", "target": target, "ttl": 300} for target in aliases]
    return CheckOutcome(
        "ok",
        data={
            "addresses": list(addresses),
            "cname": chain,
            "canonical_name": aliases[-1] if aliases else "www.example.com",
        },
    )


class FakeProvider:
    def __init__(self, table: dict[str, IpLocation] | None = None) -> None:
        self.table = table or {}

    def lookup(self, ip: str) -> IpLocation:
        return self.table.get(ip, IpLocation(ip=ip))

    def databases(self) -> list[DatabaseInfo]:
        return [DatabaseInfo("city", "DBIP-City-Lite", "2026-10-01")]


class Reverse:
    def __init__(
        self, names: dict[str, list[str]] | None = None, errors: dict[str, str] | None = None
    ) -> None:
        self.names = names or {}
        self.errors = errors or {}
        self.calls: list[str] = []

    def __call__(self, config: Any, ip: str) -> tuple[list[str], str | None]:
        self.calls.append(ip)
        return self.names.get(ip, []), self.errors.get(ip)


def run(
    provider: Any,
    dns: CheckOutcome | None,
    reverse: Reverse | None = None,
) -> CheckOutcome:
    check = IpCheck(provider_factory=lambda config: provider, reverse_lookup=reverse or Reverse())
    previous = {} if dns is None else {"dns": dns}
    ctx = CheckContext("example.com", "www.example.com", CONFIG, httpx.Client(), previous)
    return check.run(ctx)


def swiss(ip: str = "85.1.1.1") -> IpLocation:
    return IpLocation(ip, "CH", "Switzerland", "EU", "Bern", "Bern", 46.85, 7.68, 3303, "Swisscom")


def german(ip: str = "46.4.0.1") -> IpLocation:
    return IpLocation(
        ip, "DE", "Germany", "EU", "Saxony", "Falkenstein", 50.4, 12.3, 24940, "Hetzner"
    )


def cloudflare(ip: str = "104.21.58.94") -> IpLocation:
    return IpLocation(
        ip, "CA", "Canada", "NA", "Ontario", "Toronto", 43.6, -79.4, 13335, "Cloudflare"
    )


# ------------------------------------------------------------------------------ the facts


def test_every_public_address_is_located_and_the_countries_are_summarised() -> None:
    provider = FakeProvider({"85.1.1.1": swiss(), "46.4.0.1": german()})
    outcome = run(provider, dns_outcome("85.1.1.1", "46.4.0.1"))

    assert (outcome.status, outcome.source) == ("ok", "dbip")
    data = outcome.data
    assert data["countries"] == ["CH", "DE"] and data["edge"] is False and data["all_edge"] is False
    first = data["addresses"][0]
    assert (first["ip"], first["found"], first["country"], first["city"]) == (
        "85.1.1.1",
        True,
        "CH",
        "Bern",
    )
    assert (first["asn"], first["organisation"], first["network"]) == (3303, "Swisscom", None)
    assert data["databases"] == [{"kind": "city", "type": "DBIP-City-Lite", "build": "2026-10-01"}]


def test_a_cdn_as_number_marks_the_address_as_an_edge() -> None:
    outcome = run(FakeProvider({"104.21.58.94": cloudflare()}), dns_outcome("104.21.58.94"))
    network = outcome.data["addresses"][0]["network"]
    assert network == {"name": "Cloudflare", "kind": "cdn", "edge": True}
    assert (outcome.data["edge"], outcome.data["all_edge"]) == (True, True)


def test_a_mix_of_edge_and_origin_addresses_is_edge_but_not_all_edge() -> None:
    provider = FakeProvider({"104.21.58.94": cloudflare(), "85.1.1.1": swiss()})
    data = run(provider, dns_outcome("104.21.58.94", "85.1.1.1")).data
    assert (data["edge"], data["all_edge"]) == (True, False)


def test_a_cdn_name_in_the_cname_chain_makes_an_aws_address_an_edge() -> None:
    aws = IpLocation(
        "13.224.1.1", "DE", "Germany", "EU", None, "Frankfurt", None, None, 16509, "Amazon"
    )
    outcome = run(
        FakeProvider({"13.224.1.1": aws}),
        dns_outcome("13.224.1.1", aliases=("d111111abcdef8.cloudfront.net",)),
    )
    assert outcome.data["addresses"][0]["network"]["name"] == "Amazon CloudFront"
    assert outcome.data["all_edge"] is True


def test_reverse_dns_names_are_kept_bounded_and_help_to_classify() -> None:
    ptr = [f"server-{n}.fra50.r.cloudfront.net" for n in range(MAX_PTR_NAMES + 3)]
    ptr[0] = "x" * (MAX_NAME + 50) + ".fra50.r.cloudfront.net"
    aws = IpLocation("13.224.1.1", "DE", "Germany", "EU", None, None, None, None, 16509, "Amazon")
    outcome = run(
        FakeProvider({"13.224.1.1": aws}),
        dns_outcome("13.224.1.1"),
        Reverse({"13.224.1.1": ptr}),
    )
    entry = outcome.data["addresses"][0]
    assert len(entry["ptr"]) == MAX_PTR_NAMES and all(len(n) <= MAX_NAME for n in entry["ptr"])
    assert entry["network"]["name"] == "Amazon CloudFront"  # recognised from the reverse name


# ------------------------------------------------------------------------------ problems stay typed


def test_resolver_trouble_is_recorded_and_stops_further_reverse_lookups() -> None:
    reverse = Reverse(errors={"85.1.1.1": "timeout"})
    outcome = run(
        FakeProvider({"85.1.1.1": swiss(), "46.4.0.1": german()}),
        dns_outcome("85.1.1.1", "46.4.0.1"),
        reverse,
    )
    assert reverse.calls == ["85.1.1.1"]  # not a timeout per address
    first, second = outcome.data["addresses"]
    assert (first["ptr_error"], second["ptr_error"]) == ("timeout", None)
    assert outcome.status == "ok"  # the locations do not depend on reverse DNS


def test_a_servfail_for_one_address_does_not_stop_the_others() -> None:
    reverse = Reverse(errors={"85.1.1.1": "servfail"}, names={"46.4.0.1": ["static.hetzner.de"]})
    outcome = run(
        FakeProvider({"85.1.1.1": swiss(), "46.4.0.1": german()}),
        dns_outcome("85.1.1.1", "46.4.0.1"),
        reverse,
    )
    assert reverse.calls == ["85.1.1.1", "46.4.0.1"]
    assert outcome.data["addresses"][1]["ptr"] == ["static.hetzner.de"]


def test_addresses_the_databases_do_not_know_are_no_data_not_ok() -> None:
    outcome = run(FakeProvider(), dns_outcome("9.9.9.9"))
    assert (outcome.status, outcome.reason_code) == ("no_data", "not_in_database")
    assert outcome.data["addresses"][0]["found"] is False and outcome.data["countries"] == []


def test_missing_databases_are_unavailable_with_their_reason() -> None:
    class Broken:
        def lookup(self, ip: str) -> IpLocation:
            raise GeoUnavailableError("datasets_missing")

        def databases(self) -> list[DatabaseInfo]:
            return []

    outcome = run(Broken(), dns_outcome("85.1.1.1"))
    assert (outcome.status, outcome.reason_code) == ("unavailable", "datasets_missing")
    assert outcome.data == {"addresses": ["85.1.1.1"]}


def test_without_a_usable_address_the_check_is_skipped() -> None:
    assert run(FakeProvider(), dns_outcome()).status == "skipped"
    assert run(FakeProvider(), None).reason_code == "no_public_address"


def test_the_number_of_addresses_is_bounded() -> None:
    many = [f"46.4.0.{n}" for n in range(1, MAX_ADDRESSES + 5)]
    outcome = run(FakeProvider({ip: german(ip) for ip in many}), dns_outcome(*many))
    assert len(outcome.data["addresses"]) == MAX_ADDRESSES


# ------------------------------------------------------------------------------ with real databases


def test_the_real_provider_reads_the_configured_directory(tmp_path: Path) -> None:
    install_databases(tmp_path)
    check = IpCheck(reverse_lookup=Reverse())  # the default provider: files in DATASETS_DIR
    previous = {"dns": dns_outcome("85.1.1.1", "2606:4700:3035::6815:3a5e")}
    ctx = CheckContext(
        "example.com",
        "www.example.com",
        {**CONFIG, "DATASETS_DIR": str(tmp_path)},
        httpx.Client(),
        previous,
    )
    outcome = check.run(ctx)

    assert outcome.status == "ok"
    assert outcome.data["countries"] == ["CA", "CH"]
    swiss_entry, cloudflare_entry = outcome.data["addresses"]
    assert (swiss_entry["city"], swiss_entry["asn"], swiss_entry["network"]) == ("Bern", 3303, None)
    assert cloudflare_entry["network"]["edge"] is True  # Cloudflare, found by its AS number
    assert [d["kind"] for d in outcome.data["databases"]] == ["city", "asn"]


def test_a_missing_directory_means_unavailable_not_an_empty_result(tmp_path: Path) -> None:
    check = IpCheck(
        provider_factory=lambda config: DbIpProvider(tmp_path / "nothing"), reverse_lookup=Reverse()
    )
    ctx = CheckContext(
        "example.com", "www.example.com", CONFIG, httpx.Client(), {"dns": dns_outcome("85.1.1.1")}
    )
    assert check.run(ctx).reason_code == "datasets_missing"
