"""Downloading exports and opening the report: who may, what comes back, what the report says."""

from __future__ import annotations

import csv
import io
import json
import re
import uuid
from datetime import timedelta
from pathlib import Path

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import CheckResult, Finding, FindingDisposition, Scan, User
from app.models.base import utc_now
from app.service import decisions
from app.service import findings as findings_service
from app.service.export import CSV_BOM
from tests.helpers import audit_rows, create_assessment, create_user, load_script, login_as
from tests.test_decisions import SPF, TLS
from tests.test_findings_service import RULES_CONFIG, populated_scan
from tests.test_languages import forget_the_language
from tests.test_summary import evaluated

Finished = tuple[FlaskClient, Scan, dict[str, Finding]]

DISCOVERY = {
    "hosts": [],
    "counts": {"names_seen": 9, "out_of_scope": 2},
    "wildcard_patterns": ["*.example.com"],
    "planned": {"dropped_by_cap": 3},
    "sources": [
        {"source": "ctlogs", "status": "ok", "names": 7, "pages": 1},
        {"source": "certspotter", "status": "ok", "names": 7, "pages": 1, "truncated": True},
        {"source": "crtsh", "status": "error", "reason_code": "http_404", "names": 0, "pages": 0},
    ],
}
SOURCES = {"ip": "dbip", "http": "http-probe", "tls": "tls-probe", "ports": "internetdb"}


@pytest.fixture
def finished(client: FlaskClient, db_session: Session) -> Finished:
    scan, rows = evaluated(db_session)
    for row in db_session.scalars(select(CheckResult).where(CheckResult.scan_id == scan.id)):
        if row.check_key == "discovery":
            row.status, row.data = "ok", DISCOVERY
        row.source = SOURCES.get(row.check_key, row.source)
    db_session.commit()
    login_as(client, db_session.get(User, scan.requested_by))
    return client, scan, rows


def url(scan: Scan, what: str) -> str:
    return f"/assessments/{scan.assessment_id}/{what}"


ALL = ("report", "export/scan.json", "export/hosts.csv", "export/findings.csv")


def decide(
    session: Session, scan: Scan, finding: Finding, status: str, reason: str, review_by: str = ""
) -> User:
    user = session.get(User, scan.requested_by)
    assert user is not None
    decisions.decide(
        session, scan.assessment_id, finding, user,
        status=status, reason=reason, review_by=review_by, today=utc_now().date(),
    )  # fmt: skip
    session.commit()
    return user


# ----- who may


@pytest.mark.parametrize("what", ALL)
def test_exports_need_a_login(finished: Finished, what: str) -> None:
    client, scan, _ = finished
    with client.session_transaction() as state:
        state.clear()
    response = client.get(url(scan, what))
    assert response.status_code == 302 and "/login" in response.headers["Location"]


@pytest.mark.parametrize("what", ALL)
def test_a_stranger_gets_nothing_not_even_a_hint(
    finished: Finished, db_session: Session, what: str
) -> None:
    client, scan, _ = finished
    login_as(client, create_user(db_session))
    assert client.get(url(scan, what)).status_code == 404
    assert client.get(f"/assessments/{uuid.uuid4()}/{what}").status_code == 404


@pytest.mark.parametrize("what", ALL)
def test_exports_are_read_only(finished: Finished, what: str) -> None:
    client, scan, _ = finished
    assert client.post(url(scan, what)).status_code == 405


@pytest.mark.parametrize("what", ALL)
def test_there_is_nothing_to_export_before_a_scan_has_finished(
    client: FlaskClient, db_session: Session, what: str
) -> None:
    scan, _ = populated_scan(db_session)  # queued: not finished
    login_as(client, db_session.get(User, scan.requested_by))
    response = client.get(url(scan, what))
    assert (
        response.status_code == 302
        and response.headers["Location"] == f"/assessments/{scan.assessment_id}"
    )
    assert "Export a scan once it has finished." in client.get(
        response.headers["Location"]
    ).get_data(as_text=True)


@pytest.mark.parametrize("what", ALL)
def test_nor_before_the_first_scan(client: FlaskClient, db_session: Session, what: str) -> None:
    user = create_user(db_session)
    assessment = create_assessment(db_session, user, "fresh.example")
    login_as(client, user)
    response = client.get(f"/assessments/{assessment.id}/{what}")
    assert (
        response.status_code == 302
        and response.headers["Location"] == f"/assessments/{assessment.id}"
    )


# ----- what comes back


def test_the_json_is_a_download_that_parses(finished: Finished) -> None:
    client, scan, rows = finished
    response = client.get(url(scan, "export/scan.json"))
    assert response.status_code == 200
    assert response.headers["Content-Type"] == "application/json; charset=utf-8"
    day = scan.created_at.date().isoformat()
    assert (
        response.headers["Content-Disposition"]
        == f'attachment; filename="example.com_{day}_scan.json"'
    )
    assert response.headers["Cache-Control"] == "no-store"
    document = json.loads(response.get_data(as_text=True))
    assert document["format"]["version"] == 1 and len(document["findings"]) == len(rows)
    assert document["discovery"]["counts"]["names_seen"] == 9
    assert {a["key"] for a in document["attributions"]} >= {"ct", "dbip", "internetdb", "target"}


def test_the_csv_files_are_downloads_a_spreadsheet_can_open(finished: Finished) -> None:
    client, scan, rows = finished
    day = scan.created_at.date().isoformat()
    for what, kind, count in (("hosts", "hosts", 4), ("findings", "findings", len(rows))):
        response = client.get(url(scan, f"export/{what}.csv"))
        assert response.status_code == 200
        assert response.headers["Content-Type"] == "text/csv; charset=utf-8"
        assert (
            response.headers["Content-Disposition"]
            == f'attachment; filename="example.com_{day}_{kind}.csv"'
        )
        raw = response.get_data()
        assert raw.startswith(b"\xef\xbb\xbf")  # Excel reads it as UTF-8
        parsed = list(csv.DictReader(io.StringIO(raw.decode("utf-8-sig"), newline="")))
        assert len(parsed) == count


def test_the_exports_include_what_the_team_decided(finished: Finished, db_session: Session) -> None:
    client, scan, rows = finished
    decide(db_session, scan, rows[SPF], "accepted", "The vendor sends no mail.")
    document = json.loads(client.get(url(scan, "export/scan.json")).get_data(as_text=True))
    spf = next(f for f in document["findings"] if f["rule_id"] == "SPF_MISSING")
    assert spf["status"] == "accepted" and spf["decision"]["reason"] == "The vendor sends no mail."
    text = client.get(url(scan, "export/findings.csv")).get_data(as_text=True)
    assert "The vendor sends no mail." in text and "accepted" in text


def test_a_cancelled_scan_can_be_exported_too(client: FlaskClient, db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    scan.status, scan.finished_at = "cancelled", utc_now()
    db_session.commit()
    login_as(client, db_session.get(User, scan.requested_by))
    document = json.loads(client.get(url(scan, "export/scan.json")).get_data(as_text=True))
    assert (
        document["scan"]["status"] == "cancelled"
        and document["scan"]["findings"]["state"] == "not_evaluated"
    )
    report = client.get(url(scan, "report")).get_data(as_text=True)
    assert "This scan did not finish everywhere (Cancelled)" in report


def test_every_export_is_in_the_audit_log(finished: Finished, db_session: Session) -> None:
    client, scan, _ = finished
    for what in ALL:
        client.get(url(scan, what))
    entries = audit_rows(
        db_session, "export.report", "export.json", "export.hosts_csv", "export.findings_csv"
    )
    assert [e.action for e in entries] == [
        "export.report",
        "export.json",
        "export.hosts_csv",
        "export.findings_csv",
    ]
    owner = db_session.get(User, scan.requested_by)
    assert owner is not None
    for entry in entries:
        assert entry.assessment_id == scan.assessment_id and entry.subject == str(scan.id)
        assert entry.actor_id == owner.id and entry.actor_email == owner.email
        assert entry.source == "web" and entry.remote_addr == "127.0.0.1"
    # what is exported stays out of the log
    assert not any(
        "Certificate" in repr(e.details) or "bad-tls" in repr(e.details) for e in entries
    )


# ----- the assessment page offers them


def test_the_assessment_page_offers_the_report_and_the_files_once_the_scan_is_over(
    finished: Finished,
) -> None:
    client, scan, _ = finished
    page = client.get(f"/assessments/{scan.assessment_id}").get_data(as_text=True)
    panel = page.split('id="export-title"')[1].split("</section>")[0]
    for what in ALL:
        assert f'href="{url(scan, what)}"' in panel
    assert 'target="_blank" rel="noopener"' in panel  # the report opens in its own tab


def test_it_offers_nothing_while_the_scan_runs(client: FlaskClient, db_session: Session) -> None:
    scan, _ = populated_scan(db_session)
    login_as(client, db_session.get(User, scan.requested_by))
    assert 'id="export-title"' not in client.get(f"/assessments/{scan.assessment_id}").get_data(
        as_text=True
    )


# ----- the report


def report_of(client: FlaskClient, scan: Scan) -> str:
    response = client.get(url(scan, "report"))
    assert response.status_code == 200 and response.headers["Content-Type"].startswith("text/html")
    return response.get_data(as_text=True)


def test_the_report_has_its_sections_in_order(finished: Finished) -> None:
    client, scan, _ = finished
    page = report_of(client, scan)
    headings = re.findall(r"<h2 id=\"r-[a-z]+\">([^<]+)</h2>", page)
    assert headings == [
        "1. Summary", "2. Open findings", "3. Findings the team decided about", "4. Hosts",
        "5. The domain itself", "6. Method and limits", "7. Data sources and attributions",
    ]  # fmt: skip
    assert '<h1><bdi class="font-mono">example.com</bdi></h1>' in page
    assert "Technical due diligence · external view" in page
    assert "It is not a certification, an audit or a penetration test." in page
    assert "not where data is stored or processed" in page  # what a location is not
    assert "Print or save as PDF" in page and "data-print" in page


def test_the_summary_answers_the_three_questions(finished: Finished) -> None:
    client, scan, _ = finished
    summary = report_of(client, scan).split('id="r-summary"')[1].split('id="r-open"')[0]
    assert "How secure is the external posture?" in summary and "open findings" in summary
    assert "Where is the data?" in summary and "United States" in summary and "Outside" in summary
    assert (
        "Who processes it?" in summary and "Swisscom" in summary and "Google Workspace" in summary
    )
    assert "Coverage" in summary and "Certificate names seen" in summary
    assert "outside the domain: 2 · wildcard patterns: 1 · over the limit: 3" in summary


def test_open_findings_are_grouped_by_severity_and_decided_ones_have_their_own_section(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    day = utc_now().date()
    review = (day + timedelta(days=90)).isoformat()
    user = decide(db_session, scan, rows[SPF], "accepted", "The vendor sends no mail.", review)
    decide(db_session, scan, rows[TLS], "false_positive", "A test fixture.")
    page = report_of(client, scan)
    opened = page.split('id="r-open"')[1].split('id="r-decided"')[0]
    decided = page.split('id="r-decided"')[1].split('id="r-hosts"')[0]

    assert re.findall(r"<h3>([A-Za-z]+) \(\d+\)</h3>", opened)[:2] == [
        "High",
        "Medium",
    ]  # most serious first
    assert "<h4>High · Weak certificate key</h4>" in opened and "No SPF record" not in opened
    assert "<h4>Medium · No SPF record · Accepted</h4>" in decided
    assert "<h4>High · Certificate not valid · False positive</h4>" in decided
    assert "The vendor sends no mail." in decided and "A test fixture." in decided
    assert "Accepted by the team" in decided and "Marked as a false positive by the team" in decided
    assert f"by {user.email} on {day.isoformat()} · review by {review}" in decided
    assert f"by {user.email} on {day.isoformat()}</p>" in decided  # the false positive: no review
    assert "Evidence:" in opened and "TLS certificate" in opened  # what each finding rests on


def test_a_lapsed_acceptance_is_listed_as_open_with_its_history(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    lapsed = utc_now().date() - timedelta(days=2)
    db_session.add(
        FindingDisposition(
            assessment_id=scan.assessment_id,
            fingerprint=rows[SPF].fingerprint,
            status="accepted",
            reason="For the audit.",
            decided_by=scan.requested_by,
            review_by=lapsed,
        )
    )
    db_session.commit()
    page = report_of(client, scan)
    opened = page.split('id="r-open"')[1].split('id="r-decided"')[0]
    assert "<h4>Medium · No SPF record · Acceptance expired</h4>" in opened
    assert "Accepted, but the review date has passed: the finding is open again." in opened


def test_the_hosts_and_the_domain_are_tabulated(finished: Finished) -> None:
    client, scan, _ = finished
    page = report_of(client, scan)
    hosts = page.split('id="r-hosts"')[1].split('id="r-domain"')[0]
    for name in ("bad-tls.example.com", "soon.example.com", "plain.example.com", "cdn.example.com"):
        assert name in hosts
    assert "Expired" in hosts and "Ashburn" in hosts  # TLS, and the city of a host
    domain = page.split('id="r-domain"')[1].split('id="r-method"')[0]
    assert "Email security" in domain and "Domain registration" in domain


def test_the_method_says_how_the_scan_went_about_it(finished: Finished) -> None:
    client, scan, _ = finished
    method = report_of(client, scan).split('id="r-method"')[1].split('id="r-sources"')[0]
    assert "ctlogs.dev" in method and "CertSpotter" in method and "crt.sh" in method
    assert "Answered (partial)" in method and "HTTP error 404" in method  # what each source did
    assert "At most 200 hosts are reviewed per scan." in method
    assert "3 hosts beyond the limit were not reviewed." in method
    assert "Shodan InternetDB" in method
    assert re.search(r"rule set [0-9a-f]{12}", method) and "versioned rules" in method
    assert "No finding is not a clean bill of health" in method


def test_the_sources_are_named_with_their_terms(finished: Finished) -> None:
    client, scan, _ = finished
    sources = report_of(client, scan).split('id="r-sources"')[1].split("</section>")[0]
    assert '<a class="link" href="https://db-ip.com" rel="noopener noreferrer">DB-IP.com' in sources
    assert "CC BY 4.0: IP geolocation by DB-IP.com." in sources
    assert "Free for non-commercial use only." in sources
    assert (
        "Certificate Transparency: ctlogs.dev, CertSpotter" in sources and "crt.sh" not in sources
    )


def test_the_report_obeys_the_content_security_policy(finished: Finished) -> None:
    """No inline script, style or handler: the pages are served with ``script-src 'self'``."""
    client, scan, _ = finished
    response = client.get(url(scan, "report"))
    page = response.get_data(as_text=True)
    assert "script-src 'self'" in response.headers["Content-Security-Policy"]
    assert "<style" not in page and " style=" not in page
    assert not re.search(r"\son[a-z]+=", page)
    assert re.findall(r"<script[^>]*>", page) == ['<script src="/static/js/report.js" defer>']
    assert "<form" not in page and "<button" in page  # one button: print
    assert "/static/css/app.css" in page and "/static/css/report.css" in page


def test_the_report_names_the_icons_of_the_application(finished: Finished) -> None:
    """The report is a document of its own, so a tab that shows it still has the favicon."""
    client, scan, _ = finished
    head = report_of(client, scan).split("</head>", 1)[0]
    assert '<link rel="icon" href="/static/brand/favicon.svg" type="image/svg+xml">' in head
    assert '<meta name="theme-color" content="#FFFFFF">' in head


def test_what_comes_from_the_network_or_from_people_is_escaped(
    finished: Finished, db_session: Session
) -> None:
    client, scan, rows = finished
    evil = '<img src=x onerror="alert(1)">'
    shown = "&lt;img src=x onerror=&#34;alert(1)&#34;&gt;"  # what the page may contain instead
    decide(db_session, scan, rows[SPF], "accepted", evil)
    scan.assessment.label = f"<script>alert(2)</script> {evil}"
    for row in db_session.scalars(
        select(CheckResult).where(CheckResult.scan_id == scan.id, CheckResult.check_key == "dns")
    ):
        row.data = {**row.data, "dangling_cname": True, "canonical_name": evil}
    db_session.commit()
    findings_service.evaluate_scan(
        db_session, scan, RULES_CONFIG
    )  # the alias target reaches a finding
    db_session.commit()

    page = report_of(client, scan)
    assert "<img src=x" not in page and "<script>alert" not in page
    heading = page.split('id="r-summary"')[0]
    opened = page.split('id="r-open"')[1].split('id="r-decided"')[0]
    decided = page.split('id="r-decided"')[1].split('id="r-hosts"')[0]
    assert f"&lt;script&gt;alert(2)&lt;/script&gt; {shown}" in heading  # the assessment's label
    assert shown in opened  # the alias target a name server answered with
    assert shown in decided  # what a person wrote as the reason

    # The data formats keep the text as it is: escaping is the job of whatever displays it.
    document = json.loads(client.get(url(scan, "export/scan.json")).get_data(as_text=True))
    assert document["assessment"]["label"].endswith(evil)
    reasons = {f["decision"]["reason"] for f in document["findings"] if f["decision"]}
    assert reasons == {evil}
    text = client.get(url(scan, "export/findings.csv")).get_data(as_text=True)
    rows_csv = list(csv.DictReader(io.StringIO(text.removeprefix(CSV_BOM), newline="")))
    assert {r["decision_reason"] for r in rows_csv if r["decision_reason"]} == {evil}


def test_the_report_of_a_scan_without_findings_says_nothing_was_evaluated(
    client: FlaskClient, db_session: Session
) -> None:
    scan, _ = populated_scan(db_session)
    scan.status, scan.finished_at = "completed", utc_now()
    db_session.commit()
    login_as(client, db_session.get(User, scan.requested_by))
    page = report_of(client, scan)
    opened = page.split('id="r-open"')[1].split('id="r-decided"')[0]
    assert "This scan has no findings" in opened  # not evaluated: said, not "none"
    assert "No open findings" not in opened


# ----- the language: the screens follow it, the files for tools do not


@pytest.fixture
def asked_in_german(
    finished: Finished, app: Flask, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> Finished:
    """The finished scan on an installation that offers German, with the real catalogue."""
    translations = load_script("translations")
    catalogue = translations.read_catalogue(translations.po_path("de_CH"))
    folder = tmp_path / "de_CH" / "LC_MESSAGES"
    folder.mkdir(parents=True)
    (folder / "messages.mo").write_bytes(translations.compile_mo(catalogue))
    monkeypatch.setattr("app.i18n.TRANSLATIONS_DIR", tmp_path)
    monkeypatch.setitem(app.config, "LANGUAGES", ["en", "de_CH"])
    return finished


def fetch(client: FlaskClient, path: str, language: str | None = None) -> str:
    """One page or file, as a browser that asks for ``language`` would get it. One application
    context serves the whole test and keeps the language of the last request: forget it."""
    forget_the_language()
    headers = {"Accept-Language": language} if language else {}
    return client.get(path, headers=headers).get_data(as_text=True)


def test_the_report_follows_the_language_of_the_person(asked_in_german: Finished) -> None:
    client, scan, _ = asked_in_german
    english = fetch(client, url(scan, "report"))
    german = fetch(client, url(scan, "report"), "de-CH,de;q=0.9")
    assert "1. Summary" in english and "1. Summary" not in german
    assert "1. Zusammenfassung" in german


def test_the_files_for_tools_are_english_whatever_language_the_person_has(
    asked_in_german: Finished,
) -> None:
    """Their words (titles, advice, sources) are read by programs and compared between exports:
    they must not change with the language of whoever downloads them."""
    client, scan, _ = asked_in_german
    german_asked = "de-CH,de;q=0.9"
    english_json = json.loads(fetch(client, url(scan, "export/scan.json")))
    german_json = json.loads(fetch(client, url(scan, "export/scan.json"), german_asked))
    assert german_json["findings"] == english_json["findings"]
    assert german_json["attributions"] == english_json["attributions"]
    assert any(" " in finding["title"] for finding in english_json["findings"])
    for what in ("hosts", "findings"):
        path = url(scan, f"export/{what}.csv")
        assert fetch(client, path, german_asked) == fetch(client, path)
