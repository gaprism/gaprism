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
    "USER_AGENT": "Gaprism/0.1 (+https://example.org)",
    "PORTS_PROVIDER": "auto",
    "SHODAN_API_KEY": "",
    "EXTERNAL_DOMAIN_LOOKUPS": ["rdap", "hsts_preload", "hibp"],
    "REPUTATION_RESOLVERS": ["quad9", "cloudflare"],
    "BLOCKLIST_PROVIDERS": ["phishing", "feodo"],
}


def described(**changes: Any) -> disclosure.Disclosure:
    return disclosure.describe({**DEFAULTS, **changes})


def keys(**changes: Any) -> list[str]:
    return [row.key for row in described(**changes).rows]


# ------------------------------------------------------------------------------ the list


def test_a_default_installation_names_its_recipients_and_what_waits_for_a_decision() -> None:
    result = described()
    # No ports row: without a key `auto` is off, because InternetDB's terms need a decision.
    assert keys() == ["ct", "dns", "hosts", "reputation", "rdap", "hsts_preload", "hibp"]
    by_key = {row.key: row for row in result.rows}
    assert "ctlogs.dev, CertSpotter, crt.sh" in by_key["ct"].who
    assert by_key["ct"].hosts == ("api.ctlogs.dev", "api.certspotter.com", "crt.sh")
    assert by_key["dns"].hosts == ("1.1.1.1", "8.8.8.8")
    assert by_key["reputation"].hosts == ("9.9.9.9", "1.1.1.2")  # and every host name
    assert by_key["reputation"].who == "Security DNS resolvers: Quad9, Cloudflare (1.1.1.2)"
    assert by_key["reputation"].optional and by_key["reputation"].setting == "REPUTATION_RESOLVERS"
    assert not by_key["hosts"].third_party  # the assessed servers are not a third party
    assert result.domain_to == (
        "the Certificate Transparency sources (ctlogs.dev, CertSpotter, crt.sh)",
        "the DNS resolvers",
        "the security DNS resolvers (Quad9, Cloudflare (1.1.1.2))",
        "the registry (RDAP)",
        "hstspreload.org",
        "Have I Been Pwned",
    )
    assert result.optional_off == ()
    assert [item.key for item in result.not_enabled] == ["internetdb", "urlhaus"]


def test_what_is_switched_off_is_left_out_and_named() -> None:
    result = described(EXTERNAL_DOMAIN_LOOKUPS=["hibp"])
    assert keys(EXTERNAL_DOMAIN_LOOKUPS=["hibp"]) == [
        "ct",
        "dns",
        "hosts",
        "reputation",
        "hibp",
    ]
    assert result.domain_to[-1] == "Have I Been Pwned"
    assert result.optional_off == ("the registry (RDAP)", "hstspreload.org")

    none = described(EXTERNAL_DOMAIN_LOOKUPS=[], PORTS_PROVIDER="off", REPUTATION_RESOLVERS=[])
    assert [row.key for row in none.rows] == ["ct", "dns", "hosts"]
    assert none.domain_to == (
        "the Certificate Transparency sources (ctlogs.dev, CertSpotter, crt.sh)",
        "the DNS resolvers",
    )
    assert len(none.optional_off) == 4
    assert none.optional_off[-1] == "the security DNS resolvers"


def test_the_observatory_is_opt_in_and_never_listed_as_switched_off() -> None:
    assert "observatory" not in keys()  # not in a default installation
    assert described().optional_off == ()  # and not "switched off": nobody had it on

    chosen = ["rdap", "hsts_preload", "hibp", "observatory"]
    result = described(EXTERNAL_DOMAIN_LOOKUPS=chosen)
    rows = {row.key: row for row in result.rows}
    assert list(rows)[-1] == "observatory"
    assert rows["observatory"].hosts == ("observatory-api.mdn.mozilla.net",)
    assert rows["observatory"].optional and rows["observatory"].learns_domain
    assert "public on MDN" in rows["observatory"].receives  # what it costs to ask
    assert "which see Mozilla" in rows["observatory"].receives  # the assessed servers see it
    assert result.domain_to[-1] == "Mozilla's HTTP Observatory" and result.optional_off == ()

    only = described(EXTERNAL_DOMAIN_LOOKUPS=["observatory"])
    assert [row.key for row in only.rows][-1] == "observatory"
    assert only.optional_off == (  # the three that are on by default are named when removed
        "the registry (RDAP)",
        "hstspreload.org",
        "Have I Been Pwned",
    )


def test_the_security_resolvers_follow_the_configuration() -> None:
    one = {row.key: row for row in described(REPUTATION_RESOLVERS=["quad9"]).rows}
    assert one["reputation"].who == "Security DNS resolvers: Quad9"
    assert one["reputation"].hosts == ("9.9.9.9",)
    off = described(REPUTATION_RESOLVERS=[])
    assert "reputation" not in [row.key for row in off.rows]
    assert off.optional_off == ("the security DNS resolvers",)
    assert not any("security" in name for name in off.domain_to)
    unknown = described(REPUTATION_RESOLVERS=["nobody"])  # validation refuses this at startup
    assert "reputation" not in [row.key for row in unknown.rows]


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
    keyless = ports(PORTS_PROVIDER="internetdb")  # asked for: the keyless provider
    assert keyless is not None and keyless.hosts == ("internetdb.shodan.io",)
    assert keyless.who == "Shodan InternetDB" and keyless.learns_domain is False  # addresses only
    assert ports(PORTS_PROVIDER="off") is None
    no_key = {r.key for r in described(PORTS_PROVIDER="shodan").rows}
    assert "ports" not in no_key  # shodan without a key sends nothing
    assert "ports" not in keys()  # auto without a key sends nothing either
    asked = {r.key: r for r in described(PORTS_PROVIDER="internetdb").rows}
    assert asked["ports"].who == "Shodan InternetDB"  # no key needed when it is asked for
    assert secret not in repr(described(SHODAN_API_KEY=secret))


def test_the_sources_whose_terms_need_a_decision_are_named_while_they_are_off() -> None:
    items = {item.key: item for item in described().not_enabled}
    assert list(items) == ["internetdb", "urlhaus"]
    assert items["internetdb"].enable == "PORTS_PROVIDER=internetdb"
    assert "non-commercial" in items["internetdb"].terms
    assert items["urlhaus"].enable == "BLOCKLIST_PROVIDERS=urlhaus,phishing,feodo"
    assert "paid licence" in items["urlhaus"].terms


def test_a_decision_that_has_been_made_is_not_listed() -> None:
    def waiting(**changes: Any) -> list[str]:
        return [item.key for item in described(**changes).not_enabled]

    assert waiting(PORTS_PROVIDER="internetdb") == ["urlhaus"]  # asked for
    assert waiting(PORTS_PROVIDER="off") == ["urlhaus"]  # switched off on purpose
    assert waiting(SHODAN_API_KEY="a-key") == ["urlhaus"]  # auto with a key is the host API
    assert waiting(BLOCKLIST_PROVIDERS=["urlhaus", "phishing", "feodo"]) == ["internetdb"]
    assert waiting(BLOCKLIST_PROVIDERS=[]) == ["internetdb"]  # the check is off on purpose
    assert waiting(PORTS_PROVIDER="internetdb", BLOCKLIST_PROVIDERS=["urlhaus"]) == []
    subset = {item.key: item for item in described(BLOCKLIST_PROVIDERS=["phishing"]).not_enabled}
    assert subset["urlhaus"].enable == "BLOCKLIST_PROVIDERS=urlhaus,phishing"  # keeps their choice


def test_the_assessed_servers_row_names_the_user_agent() -> None:
    row = next(r for r in described().rows if r.key == "hosts")
    assert "Gaprism/0.1 (+https://example.org)" in row.receives
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


def test_the_page_names_the_sources_that_wait_for_a_decision_until_somebody_decides(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "PORTS_PROVIDER", "auto")
    monkeypatch.setitem(app.config, "SHODAN_API_KEY", "")
    monkeypatch.setitem(app.config, "BLOCKLIST_PROVIDERS", ["phishing", "feodo"])
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    assert "Not enabled, because their terms need your decision:" in page
    assert "Shodan InternetDB" in page and "free for non-commercial use only" in page
    assert "<code>PORTS_PROVIDER=internetdb</code>" in page
    assert "may need a paid licence" in page
    assert "<code>BLOCKLIST_PROVIDERS=urlhaus,phishing,feodo</code>" in page
    assert "<bdi>Shodan InternetDB</bdi>" not in page  # nothing is sent there: no row for it
    assert "Switched off in this installation" not in page  # that is another statement

    monkeypatch.setitem(app.config, "PORTS_PROVIDER", "internetdb")
    monkeypatch.setitem(app.config, "BLOCKLIST_PROVIDERS", ["urlhaus", "phishing", "feodo"])
    decided = client.get("/assessments/new").get_data(as_text=True)
    assert "Not enabled, because their terms" not in decided
    assert "<bdi>Shodan InternetDB</bdi>" in decided  # and now it is one of the recipients


def test_the_page_follows_the_installation_and_says_what_is_off(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setitem(app.config, "EXTERNAL_DOMAIN_LOOKUPS", [])
    monkeypatch.setitem(app.config, "REPUTATION_RESOLVERS", [])
    login_as(client, create_user(db_session))
    page = client.get("/assessments/new").get_data(as_text=True)
    off = "the registry (RDAP), hstspreload.org, Have I Been Pwned, the security DNS resolvers."
    assert f"Switched off in this installation: {off}" in page
    assert "<bdi>Have I Been Pwned</bdi>" not in page  # no row for a lookup that is off
    assert "Security DNS resolvers:" not in page


def test_the_page_names_the_observatory_once_somebody_has_switched_it_on(
    app: Flask, client: FlaskClient, db_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    login_as(client, create_user(db_session))
    before = client.get("/assessments/new").get_data(as_text=True)
    assert "Mozilla" not in before  # the default installation never mentions it

    monkeypatch.setitem(
        app.config, "EXTERNAL_DOMAIN_LOOKUPS", ["rdap", "hsts_preload", "hibp", "observatory"]
    )
    page = client.get("/assessments/new").get_data(as_text=True)
    assert "Have I Been Pwned, Mozilla&#39;s HTTP Observatory." in page  # in the sentence
    assert "public on MDN and cannot be hidden" in page and "which see Mozilla" in page
    assert "Switched off in this installation" not in page


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
    opted_in = described(EXTERNAL_DOMAIN_LOOKUPS=["observatory"]).rows
    keyless = described(PORTS_PROVIDER="internetdb").rows  # off by default, so asked for here
    rows = [*described().rows, *described(SHODAN_API_KEY="a-key").rows, *keyless, *opted_in]
    missing = {name for row in rows for name in (*row.hosts, row.setting) if name not in section}
    assert not missing, f"docs/deploy.md does not mention: {sorted(missing)}"
    not_named = [host for host in disclosure.DATASET_DOWNLOADS if host not in section]
    assert not not_named, f"the downloads of `datasets update` are not in the doc: {not_named}"
    for config_key in ("CTLOGS_API_KEY", "CERTSPOTTER_TOKEN", "BLOCKED_DOMAINS"):
        assert config_key in section


def test_the_hosts_that_datasets_update_contacts_are_the_ones_listed() -> None:
    """The list the doc is checked against must be what the code downloads from."""
    from urllib.parse import urlsplit

    from app.service import blocklists, exploits
    from app.service.geo import datasets

    urls = [exploits.KEV_URL, exploits.EPSS_URL, *blocklists.URLS]
    for spec in datasets.SPECS:
        urls.append(spec.official)
        urls.extend(spec.mirrors)
    hosts = {urlsplit(url).hostname for url in urls}
    assert hosts == set(disclosure.DATASET_DOWNLOADS)
