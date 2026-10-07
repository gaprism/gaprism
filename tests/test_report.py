"""What the printable report is made of: findings grouped for reading, hosts placed, the method."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.checks.base import CheckOutcome
from app.models import CheckResult, Scan
from app.service import decisions
from app.service import export as export_service
from app.service.export import ExportData, Places
from app.service.findings import SEVERITIES
from app.service.report import MAX_PLACES_SHOWN, ReportView, build_report
from tests.test_decisions import SPF, TLS, user_of
from tests.test_findings_service import RULES_CONFIG, add_host, populated_scan
from tests.test_summary import evaluated

NOW = datetime(2026, 10, 5, 12, 30, tzinfo=UTC)


def export_of(session: Session, scan: Scan) -> ExportData:
    return export_service.build_export(session, scan.assessment, scan, RULES_CONFIG, now=NOW)


def report_of(session: Session, scan: Scan) -> ReportView:
    return build_report(export_of(session, scan))


def entry(
    ip: str,
    country: str | None,
    city: str | None = None,
    *,
    edge: bool = False,
    network: str | None = "Example Net",
) -> dict[str, Any]:
    return {
        "ip": ip,
        "found": bool(country),
        "country": country,
        "city": city,
        "asn": 64500,
        "organisation": network,
        "network": {"name": network, "edge": edge} if network else None,
        "ptr": [],
        "ptr_error": None,
    }


def located(*entries: dict[str, Any]) -> CheckOutcome:
    return CheckOutcome(
        "ok",
        data={
            "addresses": list(entries),
            "countries": sorted({e["country"] for e in entries if e["country"]}),
            "edge": any(e["network"] and e["network"]["edge"] for e in entries),
            "all_edge": all(e["network"] and e["network"]["edge"] for e in entries),
            "databases": [],
        },
        source="dbip",
    )


def location_of(session: Session, scan: Scan, hostname: str) -> str:
    return next(h for h in report_of(session, scan).hosts if h.hostname == hostname).location


# ----- findings in reading order


def test_open_findings_are_grouped_by_severity_most_serious_first(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    data = export_of(db_session, scan)
    report = build_report(data)

    assert [g.severity for g in report.open_groups] == [
        s for s in SEVERITIES if any(f.severity == s for f in data.open_findings)
    ]
    assert all(f.severity == g.severity for g in report.open_groups for f in g.findings)
    grouped = [f.id for g in report.open_groups for f in g.findings]
    assert sorted(grouped) == sorted(f.id for f in data.open_findings)  # each one exactly once


def test_what_the_team_decided_is_listed_apart_and_not_among_the_open(db_session: Session) -> None:
    scan, rows = evaluated(db_session)
    user = user_of(db_session, scan)
    for rule, status, reason in (
        (SPF, "accepted", "Known."),
        (TLS, "false_positive", "Fixture."),
    ):
        decisions.decide(
            db_session, scan.assessment_id, rows[rule], user,
            status=status, reason=reason, today=NOW.date(),
        )  # fmt: skip
    db_session.commit()
    report = report_of(db_session, scan)

    assert {f.rule_id for f in report.decided} == {"SPF_MISSING", "TLS_INVALID"}
    assert {f.status for f in report.decided} == {"accepted", "false_positive"}
    opened = {f.rule_id for g in report.open_groups for f in g.findings}
    assert not opened & {"SPF_MISSING", "TLS_INVALID"}
    assert all(f.decision and f.decision.reason for f in report.decided)


def test_a_scan_that_was_never_evaluated_has_no_groups_and_says_so(db_session: Session) -> None:
    scan, _ = populated_scan(db_session)  # results, but the rules never ran
    scan.status, scan.finished_at = "completed", NOW
    db_session.commit()
    report = report_of(db_session, scan)
    assert report.data.findings_state == "not_evaluated"
    assert report.open_groups == () and report.decided == ()  # not "no findings"


# ----- hosts and places


def test_places_name_each_city_then_the_countries_without_one() -> None:
    places = Places(
        countries=("CH", "DE", "US"),
        cities=(("Bern", "CH"), ("Ashburn", "US")),
        networks=(),
        any_edge=False,
        all_edge=False,
    )
    assert places.named() == ("Bern, CH", "Ashburn, US", "DE")
    assert Places((), (), (), False, False).named() == ()


def test_a_host_is_placed_by_its_own_addresses_with_their_cities(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    add_host(
        db_session,
        scan,
        "two.example.com",
        {"ip": located(entry("192.0.2.1", "CH", "Bern"), entry("192.0.2.2", "US", "Ashburn"))},
    )
    add_host(db_session, scan, "nocity.example.com", {"ip": located(entry("192.0.2.3", "DE"))})
    assert location_of(db_session, scan, "two.example.com") == "Bern, CH; Ashburn, US"
    assert location_of(db_session, scan, "nocity.example.com") == "DE"


def test_a_cdn_edge_is_not_a_place_and_is_said_so(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    edge = entry("192.0.2.10", "US", "San Francisco", edge=True, network="Cloudflare")
    own = entry("192.0.2.11", "CH", "Zurich")
    add_host(db_session, scan, "edge.example.com", {"ip": located(edge)})
    add_host(db_session, scan, "mixed.example.com", {"ip": located(edge, own)})
    assert location_of(db_session, scan, "edge.example.com") == "Cloudflare edge"
    assert location_of(db_session, scan, "mixed.example.com") == "Zurich, CH · incl. CDN edge"


def test_a_host_that_could_not_be_located_says_why_instead_of_nothing(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    add_host(
        db_session, scan, "gone.example.com", {"ip": CheckOutcome("unavailable", "no_database")}
    )
    add_host(db_session, scan, "unchecked.example.com", {"dns": CheckOutcome("ok", data={})})
    assert location_of(db_session, scan, "gone.example.com") not in ("", "Not checked")
    assert location_of(db_session, scan, "unchecked.example.com") == "Not checked"


def test_a_long_list_of_places_is_cut_and_marked(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    many = [entry(f"192.0.2.{n}", "CH", f"City{n}") for n in range(1, MAX_PLACES_SHOWN + 3)]
    add_host(db_session, scan, "wide.example.com", {"ip": located(*many)})
    text = location_of(db_session, scan, "wide.example.com")
    assert text.count(", CH") == MAX_PLACES_SHOWN and text.endswith("…")


# ----- the method


def test_the_method_is_read_from_what_the_scan_stored(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    for row in db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)):
        if row.check_key == "discovery":
            row.status = "ok"
            row.data = {
                "sources": [
                    {"source": "ctlogs", "status": "ok", "names": 5},
                    {"source": "crtsh", "status": "unavailable", "reason_code": "rate_limited"},
                ],
                "planned": {"dropped_by_cap": 4},
            }
        elif row.check_key == "dns":
            row.source = "dns:1.1.1.1,9.9.9.9"
        elif row.check_key == "ports":
            row.source = "shodan"
    db_session.commit()
    method = report_of(db_session, scan).method

    assert [(s.name, s.status, s.reason, s.names) for s in method.discovery] == [
        ("ctlogs.dev", "ok", None, 5),
        ("crt.sh", "unavailable", "rate_limited", 0),
    ]
    assert method.dropped_by_limit == 4 and method.host_limit == scan.options["max_hosts"]
    assert method.resolvers == "1.1.1.1,9.9.9.9" and method.ports_providers == ("Shodan host API",)
    assert method.evaluated_at and method.findings_errors == ()
    assert method.security_resolvers == ()  # no host of this scan was asked about its reputation


def test_the_security_resolvers_every_host_name_went_to_are_named_in_the_method(
    db_session: Session,
) -> None:
    scan, _ = evaluated(db_session)
    add_host(
        db_session,
        scan,
        "asked.example.com",
        {"reputation": CheckOutcome("ok", data={"blocked_by": []}, source="security-dns:quad9")},
    )
    method = report_of(db_session, scan).method
    assert method.security_resolvers == ("Quad9",)


def test_the_blocklists_that_were_looked_in_are_named_with_the_day_they_are_from(
    db_session: Session,
) -> None:
    scan, _ = evaluated(db_session)
    assert report_of(db_session, scan).method.blocklists == ()

    def feeds(*items: tuple[str, str, str]) -> dict[str, Any]:
        return {"feeds": [{"key": k, "name": n, "as_of": d} for k, n, d in items], "names": []}

    urlhaus, feodo = ("urlhaus", "abuse.ch URLhaus"), ("feodo", "abuse.ch Feodo Tracker")
    both = feeds((*feodo, "2026-10-07"), (*urlhaus, "2026-10-07"))
    add_host(db_session, scan, "a.example.com", {"blocklists": CheckOutcome("ok", data=both)})
    older = feeds((*urlhaus, "2026-10-05"))
    add_host(db_session, scan, "b.example.com", {"blocklists": CheckOutcome("ok", data=older)})
    odd = {"feeds": ["nonsense", {"key": "carrier-pigeon", "name": "x", "as_of": "2026-10-01"}]}
    add_host(db_session, scan, "c.example.com", {"blocklists": CheckOutcome("ok", data=odd)})
    gone = feeds(("phishing", "Phishing.Database", "2026-10-07"))
    add_host(
        db_session, scan, "d.example.com",
        {"blocklists": CheckOutcome("unavailable", "blocklists_missing", data=gone)},
    )  # fmt: skip
    # the providers' order, the oldest day of each, and nothing from a check that did not answer
    assert report_of(db_session, scan).method.blocklists == (
        "abuse.ch URLhaus (2026-10-05)",
        "abuse.ch Feodo Tracker (2026-10-07)",
    )


def test_the_method_says_when_the_name_went_to_mozillas_observatory(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    assert report_of(db_session, scan).method.observatory is False
    db_session.add(
        CheckResult(
            scan_id=scan.id,
            host_id=None,
            check_key="observatory",
            status="skipped",
            reason_code="disabled",
            data={"domain": "example.com"},
            source=None,  # switched off: nothing was sent
            collected_at=NOW,
        )
    )
    db_session.commit()
    assert report_of(db_session, scan).method.observatory is False
    row = db_session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id, CheckResult.check_key == "observatory"
        )
    ).one()
    row.status, row.reason_code, row.source = "error", "timeout", "mdn-observatory"
    db_session.commit()  # asked, and it did not answer: the name was still sent
    assert report_of(db_session, scan).method.observatory is True


def test_the_method_names_the_checks_the_installation_switched_off(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    assert report_of(db_session, scan).method.switched_off == ()
    rows = {
        (row.check_key, row.host_id is None): row
        for row in db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id))
    }
    for key in ("hsts_preload", "observatory"):
        if (key, True) not in rows:
            db_session.add(
                CheckResult(
                    scan_id=scan.id, host_id=None, check_key=key, status="ok", data={},
                    source=None, collected_at=NOW,
                )
            )  # fmt: skip
    db_session.commit()
    for row in db_session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id,
            CheckResult.check_key.in_(["hsts_preload", "observatory", "registration", "ports"]),
        )
    ):
        row.status, row.reason_code = "skipped", "disabled"  # PORTS_PROVIDER=off, lookups off
    db_session.commit()
    method = report_of(db_session, scan).method
    # each name once, in the order the pages show them; the opt-in check nobody enabled is not
    # "switched off"
    assert method.switched_off == (
        "Open ports and CVEs",
        "Domain registration",
        "HSTS preload list",
    )


def test_a_scan_without_discovery_data_has_an_empty_method_not_a_crash(db_session: Session) -> None:
    scan, _ = evaluated(db_session)
    for row in db_session.scalars(
        select(CheckResult).where(
            CheckResult.scan_id == scan.id, CheckResult.check_key == "discovery"
        )
    ):
        db_session.delete(row)
    db_session.commit()
    method = report_of(db_session, scan).method
    assert method.discovery == () and method.dropped_by_limit == 0
    assert method.resolvers is None  # the scenario's DNS results name no resolver
    assert method.location_databases == (("DBIP-City-Lite", "2026-10-01"),)  # from the IP check
