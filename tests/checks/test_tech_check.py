"""The technology check: what it recognises from what the other checks stored. No network."""

from __future__ import annotations

import datetime
import json
from typing import Any

import httpx
import pytest

from app.checks.base import CheckContext, CheckOutcome, waits_for
from app.checks.tech import (
    MAX_EVIDENCE,
    MAX_THIRD_PARTIES,
    SOURCE,
    Inputs,
    TechCheck,
    match,
    read_inputs,
    recognise,
)
from app.checks.tech_rules import BY_KEY, RULESET_DATE, TECHNOLOGIES, Tech

TODAY = datetime.date(2026, 10, 7)
HOST = "www.example.com"


def inputs(
    headers: dict[str, str] | None = None,
    cookies: list[str] | None = None,
    generator: list[str] | None = None,
    resources: list[tuple[str, str | None, str]] | None = None,
    markers: list[str] | None = None,
    networks: list[str] | None = None,
    cnames: list[str] | None = None,
    inline_hosts: list[str] | None = None,
) -> Inputs:
    return Inputs(
        headers={name: [value] for name, value in (headers or {}).items()},
        cookies=cookies or [],
        generators=generator or [],
        resources=[
            {"kind": kind, "host": host, "path": path, "version": None}
            for kind, host, path in (resources or [])
        ],
        markers=set(markers or []),
        networks=set(networks or []),
        cnames=cnames or [],
        inline_hosts=inline_hosts or [],
        page_read=True,
    )


def keys(found: list[Any]) -> list[str]:
    return [item.tech.key for item in found]


# ----------------------------------------------------------------- the ruleset matches itself


def sample(tech: Tech) -> Inputs | None:
    """The simplest input that shows ``tech``, when one can be made from its own entry."""
    if tech.hosts:
        return inputs(resources=[("script", tech.hosts[0], "/x.js")])
    if tech.markers:
        return inputs(markers=[tech.markers[0]])
    if tech.networks:
        return inputs(networks=[tech.networks[0]])
    if tech.cnames:
        return inputs(cnames=[f"x.{tech.cnames[0]}"])
    presence = [name for name, pattern in tech.headers if not pattern]
    if presence:
        return inputs(headers={presence[0]: "x"})
    return None


# What cannot be made from the entry itself: a header or cookie value, a generator text, a path.
BY_HAND: dict[str, Inputs] = {
    "akamai_bot_manager": inputs(cookies=["_abck"]),
    "keycdn": inputs(headers={"server": "keycdn-engine"}),
    "aws_elb": inputs(headers={"server": "awselb/2.0"}),
    "f5_bigip": inputs(cookies=["BIGipServerpool_web"]),
    "citrix_netscaler": inputs(cookies=["NSC_AAAC"]),
    "fortiweb": inputs(cookies=["FORTIWAFSID"]),
    "nginx": inputs(headers={"server": "nginx/1.24.0"}),
    "apache": inputs(headers={"server": "Apache/2.4.57 (Debian)"}),
    "iis": inputs(headers={"server": "Microsoft-IIS/10.0"}),
    "openresty": inputs(headers={"server": "openresty/1.21.4.1"}),
    "caddy": inputs(headers={"server": "Caddy"}),
    "envoy": inputs(headers={"server": "envoy"}),
    "tomcat": inputs(headers={"server": "Apache-Coyote/1.1"}),
    "jetty": inputs(headers={"server": "Jetty(9.4.51.v20230217)"}),
    "kestrel": inputs(headers={"server": "Kestrel"}),
    "gunicorn": inputs(headers={"server": "gunicorn/20.1.0"}),
    "lighttpd": inputs(headers={"server": "lighttpd/1.4.69"}),
    "php": inputs(headers={"x-powered-by": "PHP/8.3.1"}),
    "java": inputs(cookies=["JSESSIONID"]),
    "python": inputs(headers={"server": "WSGIServer/0.2 CPython/3.11.4"}),
    "ruby": inputs(headers={"x-runtime": "0.012345"}),
    "express": inputs(headers={"x-powered-by": "Express"}),
    "nuxt": inputs(resources=[("script", None, "/_nuxt/entry.js")]),
    "gatsby": inputs(generator=["Gatsby 5.12.0"]),
    "laravel": inputs(cookies=["laravel_session"]),
    "django": inputs(cookies=["csrftoken"]),
    "woocommerce": inputs(generator=["WooCommerce 8.3.1"]),
    "elementor": inputs(generator=["Elementor 3.18.3"]),
    "joomla": inputs(generator=["Joomla! - Open Source Content Management"]),
    "typo3": inputs(generator=["TYPO3 CMS"]),
    "hugo": inputs(generator=["Hugo 0.120.4"]),
    "jekyll": inputs(generator=["Jekyll v4.3.2"]),
    "docusaurus": inputs(generator=["Docusaurus v3.0.1"]),
    "umbraco": inputs(generator=["Umbraco"]),
    "aem": inputs(resources=[("script", None, "/etc.clientlibs/site/clientlibs.js")]),
    "prestashop": inputs(generator=["PrestaShop"]),
    "shopware": inputs(resources=[("script", None, "/bundles/storefront/storefront/js/app.js")]),
    "jquery": inputs(resources=[("script", None, "/js/jquery-3.6.0.min.js")]),
    "jquery_ui": inputs(resources=[("script", None, "/js/jquery-ui.min.js")]),
    "bootstrap": inputs(resources=[("link", None, "/css/bootstrap.min.css")]),
    "angularjs": inputs(resources=[("script", None, "/js/angular.min.js")]),
    "react": inputs(resources=[("script", None, "/js/react.production.min.js")]),
    "vue": inputs(resources=[("script", None, "/js/vue.min.js")]),
    "facebook_sdk": inputs(resources=[("script", "connect.facebook.net", "/en_US/sdk.js")]),
}


def implied_closure(key: str) -> set[str]:
    found = {key}
    for implied in BY_KEY[key].implies:
        found |= implied_closure(implied)
    return found


@pytest.mark.parametrize("tech", TECHNOLOGIES, ids=lambda tech: tech.key)
def test_every_entry_is_recognised_from_its_own_sample_and_nothing_else_is(tech: Tech) -> None:
    implied_only = {key for other in TECHNOLOGIES for key in other.implies}
    given = BY_KEY_SAMPLES.get(tech.key)
    if given is None:
        assert tech.key in implied_only, f"{tech.key}: add a sample"
        return
    shown = recognise(given)
    # the entry is found, together with what it implies, and no other entry fired by accident
    assert set(keys(shown)) == implied_closure(tech.key), keys(shown)
    assert tech.key in keys(shown)


BY_KEY_SAMPLES: dict[str, Inputs] = {
    tech.key: given
    for tech in TECHNOLOGIES
    if (given := (BY_HAND.get(tech.key) or sample(tech))) is not None
}


@pytest.mark.parametrize(
    "path",
    ["/js/script.js", "/js/scripts.min.js", "/assets/js/script.outbound-links.js", "/js/main.js"],
)
def test_a_script_with_a_common_name_is_not_taken_for_a_product(path: str) -> None:
    """Found on www.joomla.org: a file called /js/script.js is not Plausible."""
    assert recognise(inputs(resources=[("script", None, path)])) == []
    assert keys(
        recognise(inputs(resources=[("script", None, "/js/plausible.outbound-links.js")]))
    ) == ["plausible"]


def test_a_page_with_nothing_to_recognise_shows_nothing() -> None:
    assert recognise(inputs()) == []
    plain = inputs(
        headers={"content-type": "text/html", "cache-control": "no-cache", "server": "mystery"},
        cookies=["session", "lang"],
        generator=["Notepad"],
        resources=[("script", None, "/app.js"), ("link", "static.example.com", "/site.css")],
    )
    assert recognise(plain) == []


# ------------------------------------------------------------------------------ versions


@pytest.mark.parametrize(
    ("key", "given", "version"),
    [
        ("nginx", inputs(headers={"server": "nginx/1.24.0 (Ubuntu)"}), "1.24.0"),
        ("apache", inputs(headers={"server": "Apache/2.4.57 (Debian) OpenSSL/3.0.9"}), "2.4.57"),
        ("iis", inputs(headers={"server": "Microsoft-IIS/10.0"}), "10.0"),
        ("php", inputs(headers={"x-powered-by": "PHP/8.1.2-1ubuntu2.14"}), "8.1.2"),
        ("aspnet", inputs(headers={"x-aspnet-version": "4.0.30319"}), "4.0.30319"),
        ("python", inputs(headers={"server": "Werkzeug/2.3.7 Python/3.11.4"}), "3.11.4"),
        ("nextjs", inputs(headers={"x-powered-by": "Next.js 14.0.3"}), "14.0.3"),
        ("wordpress", inputs(generator=["WordPress 6.4.2"]), "6.4.2"),
        ("drupal", inputs(generator=["Drupal 10 (https://www.drupal.org)"]), "10"),
        ("joomla", inputs(generator=["Joomla! 3.10.12 - Open Source CMS"]), "3.10.12"),
        ("hugo", inputs(generator=["Hugo 0.120.4"]), "0.120.4"),
        ("ghost", inputs(generator=["Ghost 5.75"]), "5.75"),
        ("jquery", inputs(resources=[("script", None, "/assets/jquery-1.12.4.min.js")]), "1.12.4"),
        (
            "jquery",
            inputs(
                resources=[
                    ("script", "cdnjs.cloudflare.com", "/ajax/libs/jquery/3.6.0/jquery.min.js")
                ]
            ),
            "3.6.0",
        ),
        (
            "bootstrap",
            inputs(
                resources=[
                    ("link", "cdn.jsdelivr.net", "/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css")
                ]
            ),
            "5.3.2",
        ),
        (
            "angularjs",
            inputs(
                resources=[
                    ("script", "ajax.googleapis.com", "/ajax/libs/angularjs/1.8.2/angular.min.js")
                ]
            ),
            "1.8.2",
        ),
    ],
)
def test_a_version_is_read_where_the_evidence_shows_one(
    key: str, given: Inputs, version: str
) -> None:
    found = {item.tech.key: item for item in recognise(given)}
    assert found[key].version == version


def test_the_version_of_a_core_file_of_wordpress_is_not_the_one_of_a_library_in_it() -> None:
    page = inputs(
        resources=[
            ("script", None, "/wp-includes/js/jquery/jquery.min.js"),
            ("script", None, "/wp-includes/js/wp-emoji-release.min.js"),
        ]
    )
    page.resources[0]["version"] = "3.7.1"
    page.resources[1]["version"] = "6.4.2"
    found = {item.tech.key: item for item in recognise(page)}
    assert found["jquery"].version == "3.7.1" and found["wordpress"].version == "6.4.2"


def test_a_version_far_down_a_long_list_of_evidence_is_still_found() -> None:
    resources = [("script", None, f"/wp-content/plugins/p{n}/s.js") for n in range(60)]
    resources.append(("script", None, "/wp-includes/js/wp-embed.min.js"))
    page = inputs(resources=resources)
    page.resources[-1]["version"] = "6.4.2"
    found = {item.tech.key: item for item in recognise(page)}
    assert found["wordpress"].version == "6.4.2"


def test_what_is_kept_as_evidence_is_bounded() -> None:
    page = inputs(resources=[("script", None, f"/wp-content/plugins/p{n}/s.js") for n in range(60)])
    data = {item.tech.key: item for item in recognise(page)}
    assert len(data["wordpress"].evidence) == 60  # read in full for the version...
    outcome = run(page_outcomes(page))
    wordpress = next(t for t in outcome.data["technologies"] if t["key"] == "wordpress")
    assert len(wordpress["evidence"]) == MAX_EVIDENCE  # ...kept only in part


# ---------------------------------------------------------------------- what comes with what


def test_what_a_technology_implies_is_listed_as_implied_not_as_seen() -> None:
    shown = {item.tech.key: item for item in recognise(inputs(generator=["WooCommerce 8.3.1"]))}
    assert set(shown) == {"woocommerce", "wordpress", "php"}
    assert shown["woocommerce"].implied_by is None
    assert shown["wordpress"].implied_by == "WooCommerce" and shown["php"].implied_by == "WordPress"


def test_confidence_follows_the_kind_of_evidence() -> None:
    def conf(given: Inputs, key: str) -> str:
        outcome = run(page_outcomes(given))
        return next(t["confidence"] for t in outcome.data["technologies"] if t["key"] == key)

    assert conf(inputs(generator=["WordPress 6.4.2"]), "wordpress") == "high"
    wp_path = inputs(resources=[("script", None, "/wp-content/themes/x/a.js")])
    assert conf(wp_path, "wordpress") == "high"  # the layout of the product itself
    jquery_file = inputs(resources=[("script", None, "/js/jquery.min.js")])
    assert conf(jquery_file, "jquery") == "medium"  # a file name that other things may share
    assert conf(inputs(cookies=["csrftoken"]), "django") == "medium"  # the entry itself says so
    assert conf(inputs(generator=["WooCommerce 8"]), "php") == "medium"  # implied


def test_only_the_services_of_other_organisations_are_marked_as_services() -> None:
    def service(given: Inputs, key: str) -> bool:
        outcome = run(page_outcomes(given))
        return next(t["service"] for t in outcome.data["technologies"] if t["key"] == key)

    assert service(inputs(networks=["Cloudflare"]), "cloudflare") is True
    assert (
        service(
            inputs(resources=[("script", "www.google-analytics.com", "/ga.js")]), "google_analytics"
        )
        is True
    )
    assert service(inputs(headers={"server": "nginx"}), "nginx") is False
    assert service(inputs(generator=["WordPress 6"]), "wordpress") is False
    # Matomo run by the site itself is not a third party; Matomo's cloud is
    assert service(inputs(resources=[("script", None, "/matomo.js")]), "matomo") is False
    assert (
        service(inputs(resources=[("script", "cdn.matomo.cloud", "/x/matomo.js")]), "matomo")
        is True
    )


# ------------------------------------------------------------------------------ the third parties


def test_other_hosts_are_listed_with_the_vendor_when_the_ruleset_knows_it() -> None:
    page = inputs(
        resources=[
            ("script", "cdn.example.com", "/app.js"),  # the site's own domain
            ("link", "fonts.googleapis.com", "/css2"),
            ("link", "fonts.gstatic.com", ""),
            ("script", "tracker.unknown-vendor.net", "/t.js"),
            ("img", "px.unknown-vendor.net", "/p.gif"),
        ],
        inline_hosts=["www.googletagmanager.com"],
    )
    rows = run(page_outcomes(page)).data["third_parties"]
    # recognised hosts first (by domain), then the others
    assert [row["host"] for row in rows] == [
        "fonts.googleapis.com",
        "www.googletagmanager.com",
        "fonts.gstatic.com",
        "px.unknown-vendor.net",
        "tracker.unknown-vendor.net",
    ]
    by_host = {row["host"]: row for row in rows}
    assert "cdn.example.com" not in by_host  # same registrable domain as the page
    assert by_host["fonts.googleapis.com"]["vendor"] == "Google"
    assert by_host["fonts.googleapis.com"]["technology"] == "google_fonts"
    assert by_host["tracker.unknown-vendor.net"]["vendor"] is None
    assert by_host["www.googletagmanager.com"]["kinds"] == ["inline"]
    assert by_host["www.googletagmanager.com"]["vendor"] == "Google"  # named through ``owns``
    unknown_first = [row["technology"] is None for row in rows]
    assert unknown_first == sorted(unknown_first)  # recognised ones first


def test_the_list_of_third_parties_is_bounded() -> None:
    page = inputs(resources=[("script", f"h{n}.vendor{n}.net", "/a.js") for n in range(100)])
    assert len(run(page_outcomes(page)).data["third_parties"]) == MAX_THIRD_PARTIES


def test_a_host_known_to_have_served_malicious_code_is_flagged_wherever_it_is_named() -> None:
    page = inputs(
        resources=[
            ("script", "cdn.polyfill.io", "/v3/polyfill.min.js"),
            ("script", "polyfill.io.example.org", "/x.js"),
        ],
        inline_hosts=["cdn.bootcss.com"],
    )
    flagged = run(page_outcomes(page)).data["flagged"]
    assert {row["host"] for row in flagged} == {"cdn.polyfill.io", "cdn.bootcss.com"}
    assert {row["reason"] for row in flagged} == {"supply_chain_2024"}
    assert {row["host"]: row["kinds"] for row in flagged} == {
        "cdn.polyfill.io": ["script"],  # code that runs
        "cdn.bootcss.com": ["inline"],  # only named in an inline script
    }
    assert run(page_outcomes(inputs())).data["flagged"] == []


# ------------------------------------------------------------------------------ old versions


def test_a_version_past_its_end_of_life_is_reported_with_where_it_was_read() -> None:
    page = inputs(
        headers={"x-powered-by": "PHP/7.4.33"},
        resources=[
            ("script", None, "/js/jquery-1.12.4.min.js"),
            ("script", None, "/js/jquery-3.7.1.min.js"),
        ],
    )
    outdated = {row["key"]: row for row in run(page_outcomes(page)).data["outdated"]}
    assert (
        outdated["php"]["reason"] == "end_of_life" and outdated["php"]["version_from"] == "header"
    )
    assert outdated["php"]["since"] == "2022-11-28" and outdated["php"]["version"] == "7.4.33"
    assert outdated["jquery"]["reason"] == "known_vulnerable"
    assert outdated["jquery"]["version_from"] == "path" and outdated["jquery"]["since"] is None


def test_a_current_version_is_not_reported() -> None:
    page = inputs(headers={"x-powered-by": "PHP/8.3.1", "server": "nginx/1.25.3"})
    assert run(page_outcomes(page)).data["outdated"] == []


# ---------------------------------------------------------------- reading the other checks


def stored(**results: CheckOutcome) -> dict[str, CheckOutcome]:
    return dict(results)


def http_result(**data: Any) -> CheckOutcome:
    base: dict[str, Any] = {"headers": [], "cookies": [], "page": None}
    return CheckOutcome("ok", data={**base, **data}, source="http-probe")


def dns_result(*targets: str) -> CheckOutcome:
    steps = [{"name": HOST, "target": target, "ttl": 300} for target in targets]
    canonical = targets[-1] if targets else HOST
    return CheckOutcome(
        "ok", data={"cname": steps, "canonical_name": canonical, "addresses": ["93.184.216.34"]}
    )


def ip_result(*network_names: str) -> CheckOutcome:
    addresses = [
        {"ip": "93.184.216.34", "network": {"name": name, "kind": "cdn", "edge": True}}
        for name in network_names
    ]
    return CheckOutcome(
        "ok", data={"addresses": addresses or [{"ip": "93.184.216.34", "network": None}]}
    )


def run(previous: dict[str, CheckOutcome]) -> CheckOutcome:
    ctx = CheckContext(
        domain="example.com", hostname=HOST, config={}, http=httpx.Client(), previous=previous
    )
    return TechCheck(clock=lambda: TODAY).run(ctx)


def page_outcomes(given: Inputs) -> dict[str, CheckOutcome]:
    """The stored results that make ``given`` when the check reads them."""
    data: dict[str, Any] = {
        "headers": [{"name": name, "value": values[0]} for name, values in given.headers.items()],
        "cookies": [{"name": name} for name in given.cookies],
        "page": {
            "generator": given.generators,
            "resources": given.resources,
            "markers": sorted(given.markers),
            "inline_hosts": given.inline_hosts,
            "truncated": False,
        },
    }
    ip = ip_result(*given.networks) if given.networks else None
    results = {"dns": dns_result(*given.cnames), "http": http_result(**data)}
    if ip is not None:
        results["ip"] = ip
    return results


def test_the_check_reads_dns_ip_and_http_and_says_which_it_read() -> None:
    previous = stored(
        dns=dns_result("example.cdn.cloudflare.net"),
        ip=ip_result("Cloudflare"),
        http=http_result(
            headers=[
                {"name": "server", "value": "cloudflare"},
                {"name": "cf-ray", "value": "abc-ZRH"},
            ],
            cookies=[{"name": "__cf_bm"}],
            page={
                "generator": [],
                "resources": [],
                "markers": [],
                "inline_hosts": [],
                "truncated": False,
            },
        ),
    )
    outcome = run(previous)
    assert (outcome.status, outcome.source) == ("ok", SOURCE)
    assert outcome.data["sources"] == ["dns", "ip", "http"] and outcome.data["edge"] == [
        "Cloudflare"
    ]
    cloudflare = outcome.data["technologies"][0]
    assert cloudflare["key"] == "cloudflare" and cloudflare["confidence"] == "high"
    assert {e["kind"] for e in cloudflare["evidence"]} == {"header", "cookie", "network", "cname"}
    assert outcome.data["page"] == {"read": True, "truncated": False, "redirected_to": None}
    assert outcome.data["ruleset"] == RULESET_DATE


def test_without_a_readable_page_only_headers_dns_and_network_speak_and_it_says_so() -> None:
    previous = stored(
        dns=dns_result("shops.myshopify.com"),
        http=CheckOutcome("no_data", "no_web_server", {"https_error": "refused"}),
    )
    outcome = run(previous)
    assert outcome.status == "ok" and outcome.data["page"]["read"] is False
    assert outcome.data["sources"] == ["dns"]
    assert [t["key"] for t in outcome.data["technologies"]] == ["shopify"]
    assert outcome.data["technologies"][0]["evidence"][0]["kind"] == "cname"


def test_a_failed_result_gives_no_input_and_a_missing_one_neither() -> None:
    assert read_inputs({}).sources == []
    broken = read_inputs(
        {
            "http": CheckOutcome(
                "error", "timeout", {"headers": [{"name": "server", "value": "nginx"}]}
            )
        }
    )
    assert broken.headers == {} and broken.sources == []


def test_a_page_of_another_host_is_not_read_as_this_hosts() -> None:
    previous = stored(
        dns=dns_result(),
        http=http_result(
            cross_host_final=True,
            final_url="https://shop.myshopify.com/",
            headers=[{"name": "server", "value": "nginx/1.24.0"}],
            cookies=[{"name": "laravel_session"}],
            page={
                "generator": ["WordPress 6.4.2"],
                "resources": [{"kind": "script", "host": "cdn.polyfill.io", "path": "/p.js"}],
                "markers": ["gtm"],
                "inline_hosts": [],
                "truncated": False,
            },
        ),
    )
    data = run(previous).data
    assert data["page"] == {
        "read": False,
        "truncated": False,
        "redirected_to": "shop.myshopify.com",
    }
    found = {t["key"]: t for t in data["technologies"]}
    assert set(found) == {
        "shopify"
    }  # not nginx, Laravel, WordPress or Tag Manager: not this host's
    assert found["shopify"]["evidence"] == [
        {"kind": "host", "detail": "shop.myshopify.com (redirect)"}
    ]
    assert [(p["host"], p["kinds"]) for p in data["third_parties"]] == [
        ("shop.myshopify.com", ["redirect"])
    ]
    assert data["flagged"] == [] and data["sources"] == ["dns", "http"]


def test_a_redirect_to_a_host_known_for_malware_is_flagged_as_a_redirect() -> None:
    previous = stored(
        dns=dns_result(),
        http=http_result(cross_host_final=True, final_url="https://cdn.polyfill.io/"),
    )
    assert [(f["host"], f["kinds"]) for f in run(previous).data["flagged"]] == [
        ("cdn.polyfill.io", ["redirect"])
    ]


def test_the_services_a_page_uses_are_listed_apart_from_the_edge_and_the_software() -> None:
    page = inputs(
        headers={"server": "cloudflare", "x-powered-by": "PHP/8.3.1"},
        generator=["WordPress 6.4.2"],
        resources=[
            ("script", "www.googletagmanager.com", "/gtm.js"),
            ("script", None, "/js/hotjar.js"),  # a script of the site's own: not the service
            ("link", "fonts.googleapis.com", "/css"),
        ],
    )
    services = run(page_outcomes(page)).data["services"]
    assert {s["name"] for s in services} == {"Google Tag Manager", "Google Fonts"}
    assert all(set(s) == {"name", "vendor", "category"} for s in services)
    assert {"Cloudflare", "PHP", "WordPress"}.isdisjoint(s["name"] for s in services)


def test_an_html_page_that_the_http_check_could_not_read_as_html_has_no_page_facts() -> None:
    outcome = run(
        stored(dns=dns_result(), http=http_result(headers=[{"name": "server", "value": "nginx"}]))
    )
    assert (
        outcome.data["page"]["read"] is False and outcome.data["technologies"][0]["key"] == "nginx"
    )


def test_the_check_is_a_host_check_that_waits_for_ip_and_http_but_needs_only_dns() -> None:
    check = TechCheck()
    assert (check.key, check.scope, check.needs, check.after) == (
        "tech",
        "host",
        ("dns",),
        ("ip", "http"),
    )
    assert waits_for(check) == ("dns", "ip", "http")


def test_the_whole_result_is_plain_json_and_nothing_is_recognised_twice() -> None:
    page = inputs(
        headers={"server": "nginx/1.24.0", "x-powered-by": "PHP/8.1.2"},
        generator=["WordPress 6.4.2"],
        resources=[
            ("script", None, "/wp-includes/js/jquery/jquery.min.js"),
            ("link", "fonts.googleapis.com", "/css"),
        ],
    )
    data = run(page_outcomes(page)).data
    assert json.loads(json.dumps(data)) == data
    names = [t["key"] for t in data["technologies"]]
    assert len(names) == len(set(names))
    assert match(BY_KEY["nginx"], page)[0].detail == "server: nginx/1.24.0"
