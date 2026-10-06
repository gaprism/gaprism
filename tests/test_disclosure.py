"""What leaves the network: the list a page shows follows the configuration, and the docs agree."""

from __future__ import annotations

from typing import Any

import pytest
from flask import Flask
from flask.testing import FlaskClient
from sqlalchemy.orm import Session

from app.service import disclosure
from tests.helpers import PROJECT_ROOT, create_user, login_as

DEFAULTS: dict[str, Any] = {
    "CT_SOURCES": ["ctlogs", "certspotter", "crtsh"],
    "EGRESS_DNS_RESOLVERS": ["1.1.1.1", "8.8.8.8"],
    "USER_AGENT": "WebDueDiligence/0.1 (+https://example.org)",
    "PORTS_PROVIDER": "auto",
    "SHODAN_API_KEY": "",
    "EXTERNAL_DOMAIN_LOOKUPS": ["rdap", "hsts_preload", "hibp"],
}


def described(**changes: Any) -> disclosure.Disclosure:
    return disclosure.describe({**DEFAULTS, **changes})


def keys(**changes: Any) -> list[str]:
    return [row.key for row in described(**changes).rows]


# ------------------------------------------------------------------------------ the list


def test_a_default_installation_names_every_recipient() -> None:
    result = described()
    assert keys() == ["ct", "dns", "hosts", "ports", "rdap", "hsts_preload", "hibp"]
    by_key = {row.key: row for row in result.rows}
    assert "ctlogs.dev, CertSpotter, crt.sh" in by_key["ct"].who
    assert by_key["ct"].hosts == ("api.ctlogs.dev", "api.certspotter.com", "crt.sh")
    assert by_key["dns"].hosts == ("1.1.1.1", "8.8.8.8")
    assert by_key["ports"].who == "Shodan InternetDB"  # no key: the keyless provider
    assert by_key["ports"].learns_domain is False  # it gets addresses, not the name
    assert not by_key["hosts"].third_party  # the assessed servers are not a third party
    assert result.domain_to == (
        "the Certificate Transparency sources (ctlogs.dev, CertSpotter, crt.sh)",
        "the DNS resolvers",
        "the registry (RDAP)",
        "hstspreload.org",
        "Have I Been Pwned",
    )
    assert result.optional_off == ()


def test_what_is_switched_off_is_left_out_and_named() -> None:
    result = described(EXTERNAL_DOMAIN_LOOKUPS=["hibp"])
    assert keys(EXTERNAL_DOMAIN_LOOKUPS=["hibp"]) == ["ct", "dns", "hosts", "ports", "hibp"]
    assert result.domain_to[-1] == "Have I Been Pwned"
    assert result.optional_off == ("the registry (RDAP)", "hstspreload.org")

    none = described(EXTERNAL_DOMAIN_LOOKUPS=[], PORTS_PROVIDER="off")
    assert [row.key for row in none.rows] == ["ct", "dns", "hosts"]
    assert none.domain_to == (
        "the Certificate Transparency sources (ctlogs.dev, CertSpotter, crt.sh)",
        "the DNS resolvers",
    )
    assert len(none.optional_off) == 3


def test_the_sources_and_resolvers_come_from_the_configuration() -> None:
    one = {row.key: row for row in described(CT_SOURCES=["crtsh"], EGRESS_DNS_RESOLVERS=[]).rows}
    assert one["ct"].who == "Certificate Transparency sources: crt.sh"
    assert one["ct"].hosts == ("crt.sh",)
    assert one["dns"].who == "The system's DNS resolver" and one["dns"].hosts == ()
    assert described(EGRESS_DNS_RESOLVERS=[]).domain_to[1] == "the system's DNS resolver"


def test_the_named_provider_follows_the_key_and_the_key_never_shows() -> None:
    secret = "SECRET-KEY-VALUE-1234"

    def ports(**changes: Any) -> disclosure.Recipient | None:
        rows = {row.key: row for row in described(SHODAN_API_KEY=secret, **changes).rows}
        return rows.get("ports")

    host_api = ports()  # auto with a key: the host API
    assert host_api is not None and host_api.who == "Shodan (host API)"
    assert host_api.hosts == ("api.shodan.io",)
    keyless = ports(PORTS_PROVIDER="internetdb")
    assert keyless is not None and keyless.hosts == ("internetdb.shodan.io",)
    assert ports(PORTS_PROVIDER="off") is None
    no_key = {r.key for r in described(PORTS_PROVIDER="shodan").rows}
    assert "ports" not in no_key  # shodan without a key sends nothing
    assert secret not in repr(described(SHODAN_API_KEY=secret))


def test_the_assessed_servers_row_names_the_user_agent() -> None:
    row = next(r for r in described().rows if r.key == "hosts")
    assert "WebDueDiligence/0.1 (+https://example.org)" in row.receives
    assert row.setting == "USER_AGENT"


# ------------------------------------------------------------------------------ the page


def test_the_new_assessment_page_says_who_receives_the_domain(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    assert "What leaves your network when you scan" in page
    assert "Scanning sends the domain name to the Certificate Transparency sources" in page
    assert "ctlogs.dev, CertSpotter, crt.sh" in page and "Have I Been Pwned" in page
    assert "Each of them also sees the address this server connects from." in page
    assert "Show who receives what" in page and "<code>EXTERNAL_DOMAIN_LOOKUPS</code>" in page
    assert "Switched off in this installation" not in page


def test_the_page_follows_the_installation_and_says_what_is_off(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "EXTERNAL_DOMAIN_LOOKUPS", [])
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    off = "the registry (RDAP), hstspreload.org, Have I Been Pwned."
    assert f"Switched off in this installation: {off}" in page
    assert "<bdi>Have I Been Pwned</bdi>" not in page  # no row for a lookup that is off


def test_what_the_page_shows_is_escaped(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "USER_AGENT", "<script>alert(1)</script>")
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    assert "<script>alert(1)" not in page and "&lt;script&gt;alert(1)" in page


def test_the_notice_is_also_there_after_a_rejected_form(
    client: FlaskClient, db_session: Session
) -> None:
    login_as(client, create_user(db_session))
    response = client.post(
        "/assessments/new", data={"domain": "not a domain", "visibility": "private"}
    )
    assert response.status_code == 200
    assert "What leaves your network when you scan" in response.get_data(as_text=True)


# ------------------------------------------------------------------------------ the documentation


def deploy_section() -> str:
    text = (PROJECT_ROOT / "docs" / "deploy.md").read_text(encoding="utf-8")
    start = text.index("## What leaves your network")
    end = text.index("\n## ", start + 1)
    return text[start:end]


def test_the_deploy_doc_names_every_recipient_and_its_setting() -> None:
    """The table in docs/deploy.md and the list the page builds are one list."""
    section = deploy_section()
    rows = [*described().rows, *described(SHODAN_API_KEY="a-key").rows]
    missing = {name for row in rows for name in (*row.hosts, row.setting) if name not in section}
    assert not missing, f"docs/deploy.md does not mention: {sorted(missing)}"
    not_named = [host for host in disclosure.DATASET_DOWNLOADS if host not in section]
    assert not not_named, f"the downloads of `datasets update` are not in the doc: {not_named}"
    for config_key in ("CTLOGS_API_KEY", "CERTSPOTTER_TOKEN", "BLOCKED_DOMAINS"):
        assert config_key in section


def test_the_hosts_that_datasets_update_contacts_are_the_ones_listed() -> None:
    """The list the doc is checked against must be what the code downloads from."""
    from urllib.parse import urlsplit

    from app.service import exploits
    from app.service.geo import datasets

    urls = [exploits.KEV_URL, exploits.EPSS_URL]
    for spec in datasets.SPECS:
        urls.append(spec.official)
        urls.extend(spec.mirrors)
    hosts = {urlsplit(url).hostname for url in urls}
    assert hosts == set(disclosure.DATASET_DOWNLOADS)
