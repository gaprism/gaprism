"""The offline provider: lookups, partial and missing databases, reloading after an update."""

from __future__ import annotations

import datetime
import threading
from pathlib import Path

import pytest

from app.service.geo import GeoUnavailableError
from app.service.geo import provider as provider_module
from app.service.geo.provider import ASN_FILE, CITY_FILE, DbIpProvider, ProviderCache
from tests.geo_helpers import (
    ASN_RECORDS,
    ASN_TYPE,
    CITY_RECORDS,
    CITY_TYPE,
    install_databases,
    place,
    write_mmdb,
)

TODAY = datetime.date(2026, 10, 4)


@pytest.fixture(autouse=True)
def always_check_for_changes(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests replace files within milliseconds; do not wait 30 seconds to notice."""
    monkeypatch.setattr(provider_module, "RELOAD_CHECK_SECONDS", 0.0)


@pytest.fixture
def provider(tmp_path: Path) -> DbIpProvider:
    install_databases(tmp_path, built=TODAY)
    return DbIpProvider(tmp_path)


# ------------------------------------------------------------------------------ lookups


def test_city_and_network_facts_are_merged(provider: DbIpProvider) -> None:
    location = provider.lookup("85.1.1.1")
    assert location.found is True
    assert (location.country, location.country_name, location.continent) == (
        "CH",
        "Switzerland",
        "EU",
    )
    assert (location.region, location.city) == ("Bern", "Bern")
    assert (location.latitude, location.longitude) == (46.85, 7.68)
    assert (location.asn, location.organisation) == (3303, "Swisscom (Schweiz) AG")
    assert location.to_data()["country"] == "CH" and "ip" not in location.to_data()


def test_ipv6_addresses_are_looked_up_too(provider: DbIpProvider) -> None:
    location = provider.lookup("2606:4700:3035::6815:3a5e")
    assert (location.country, location.city, location.asn) == ("CA", "Toronto", 13335)


def test_an_address_the_databases_do_not_know_is_a_result_not_an_error(
    provider: DbIpProvider,
) -> None:
    location = provider.lookup("9.9.9.9")
    assert location.found is False
    assert (location.country, location.city, location.asn) == (None, None, None)


def test_a_known_network_without_a_city_record_is_partly_known(provider: DbIpProvider) -> None:
    location = provider.lookup("5.9.1.1")
    assert location.found is True and location.country is None
    assert (location.asn, location.organisation) == (24940, "Hetzner Online GmbH")


def test_a_city_without_a_network_record_is_partly_known(provider: DbIpProvider) -> None:
    location = provider.lookup("93.184.216.34")  # the real database has no ASN for this range
    assert (location.country, location.city, location.asn) == ("GB", "London", None)


def test_brackets_are_tolerated_and_garbage_is_a_value_error(provider: DbIpProvider) -> None:
    assert provider.lookup("[2606:4700:3035::1]").country == "CA"
    with pytest.raises(ValueError, match="does not appear to be"):
        provider.lookup("not an address")


def test_odd_records_never_crash_a_lookup(tmp_path: Path) -> None:
    weird = {
        "1.1.1.0/24": {"country": "CH", "city": "Bern", "location": [1, 2], "subdivisions": "x"},
        "2.2.2.0/24": {"country": {"iso_code": "toolong"}, "location": {"latitude": "46.9"}},
        "3.3.3.0/24": {"city": {"names": {"de": "Zürich"}}, "country": {"iso_code": "ch"}},
        "4.4.4.0/24": {"city": {"names": {"en": "x" * 500}}},
    }
    install_databases(tmp_path, city=weird, asn={"1.1.1.0/24": {"autonomous_system_number": "x"}})
    provider = DbIpProvider(tmp_path)
    assert provider.lookup("1.1.1.1").country is None  # a string where a record was expected
    assert provider.lookup("2.2.2.2").country is None  # not a two-letter code
    assert provider.lookup("2.2.2.2").latitude is None  # a string is not a coordinate
    third = provider.lookup("3.3.3.3")
    assert (third.country, third.city) == ("CH", "Zürich")  # lower case fixed, other language used
    assert len(provider.lookup("4.4.4.4").city or "") == 100  # bounded
    assert provider.lookup("1.1.1.1").asn is None


# ---------------------------------------------------------------------------- missing or broken


def test_no_databases_at_all_is_unavailable_not_empty(tmp_path: Path) -> None:
    provider = DbIpProvider(tmp_path / "nothing-here")
    with pytest.raises(GeoUnavailableError) as raised:
        provider.lookup("8.8.8.8")
    assert raised.value.reason_code == "datasets_missing"
    assert provider.databases() == []


def test_one_database_is_enough(tmp_path: Path) -> None:
    write_mmdb(tmp_path / ASN_FILE, ASN_TYPE, ASN_RECORDS, built=TODAY)
    only_asn = DbIpProvider(tmp_path).lookup("8.8.8.8")
    assert (only_asn.asn, only_asn.country) == (15169, None)

    other = tmp_path / "city-only"
    write_mmdb(other / CITY_FILE, CITY_TYPE, CITY_RECORDS, built=TODAY)
    only_city = DbIpProvider(other).lookup("8.8.8.8")
    assert (only_city.country, only_city.asn) == ("US", None)


def test_a_broken_file_is_unreadable_and_recovers_when_replaced(tmp_path: Path) -> None:
    (tmp_path / CITY_FILE).write_bytes(b"this is not a database")
    provider = DbIpProvider(tmp_path)
    with pytest.raises(GeoUnavailableError) as raised:
        provider.lookup("8.8.8.8")
    assert raised.value.reason_code == "datasets_unreadable"

    install_databases(tmp_path, built=TODAY)
    assert provider.lookup("8.8.8.8").country == "US"


def test_an_updated_file_is_picked_up_without_a_restart(tmp_path: Path) -> None:
    write_mmdb(tmp_path / CITY_FILE, CITY_TYPE, {"85.1.1.0/24": place("CH", "Switzerland", "Bern")})
    provider = DbIpProvider(tmp_path)
    assert provider.lookup("85.1.1.1").city == "Bern"

    write_mmdb(
        tmp_path / CITY_FILE,
        CITY_TYPE,
        {"85.1.1.0/24": place("CH", "Switzerland", "Zürich"), "9.9.9.0/24": place("US", "US", "X")},
    )
    assert provider.lookup("85.1.1.1").city == "Zürich"


def test_a_database_that_disappears_makes_the_provider_unavailable_again(tmp_path: Path) -> None:
    install_databases(tmp_path, built=TODAY)
    provider = DbIpProvider(tmp_path)
    assert provider.lookup("8.8.8.8").found
    (tmp_path / CITY_FILE).unlink()
    (tmp_path / ASN_FILE).unlink()
    with pytest.raises(GeoUnavailableError):
        provider.lookup("8.8.8.8")


# ------------------------------------------------------------------------------ housekeeping


def test_databases_report_their_type_and_build_date(provider: DbIpProvider) -> None:
    assert [(d.kind, d.database_type, d.build) for d in provider.databases()] == [
        ("city", CITY_TYPE, "2026-10-04"),
        ("asn", ASN_TYPE, "2026-10-04"),
    ]


def test_one_provider_per_directory_is_shared(tmp_path: Path) -> None:
    cache = ProviderCache()
    assert cache.get(tmp_path) is cache.get(tmp_path / ".." / tmp_path.name)  # same resolved path
    assert cache.get(tmp_path) is not cache.get(tmp_path / "other")


def test_many_threads_can_look_up_at_once(provider: DbIpProvider) -> None:
    failures: list[str] = []

    def work() -> None:
        for _ in range(200):
            if (
                provider.lookup("85.1.1.1").country != "CH"
                or provider.lookup("8.8.8.8").asn != 15169
            ):
                failures.append("wrong answer")

    threads = [threading.Thread(target=work) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    assert failures == []
