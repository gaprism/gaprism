"""The reading of a home page's HTML: what it keeps, what it drops, and its bounds."""

from __future__ import annotations

import json
from typing import Any

import pytest

from app.checks.page_facts import (
    MAX_GENERATORS,
    MAX_INLINE_HOSTS,
    MAX_RESOURCES,
    MAX_TAGS,
    page_facts,
)

GTM_SNIPPET = (
    "<script>(function(w,d,s,l,i){w[l]=w[l]||[];w[l].push({'gtm.start':new Date().getTime(),"
    "event:'gtm.js'});var f=d.getElementsByTagName(s)[0],j=d.createElement(s),"
    "dl=l!='dataLayer'?'&l='+l:'';j.async=true;j.src="
    "'https://www.googletagmanager.com/gtm.js?id='+i+dl;f.parentNode.insertBefore(j,f);"
    "})(window,document,'script','dataLayer','GTM-ABC123');</script>"
)


def resources(html: str) -> list[dict[str, Any]]:
    return page_facts(html)["resources"]  # type: ignore[no-any-return]


# ------------------------------------------------------------------------------ the generator


def test_the_generator_tag_is_read_whatever_the_case_and_spacing() -> None:
    html = '<meta NAME="Generator" content="  WordPress   6.4.2 ">'
    assert page_facts(html)["generator"] == ["WordPress 6.4.2"]


def test_generators_are_deduplicated_cut_and_limited() -> None:
    same = (
        '<meta name="generator" content="Hugo 0.120"><meta name="generator" content="Hugo 0.120">'
    )
    assert page_facts(same)["generator"] == ["Hugo 0.120"]
    many = "".join(f'<meta name="generator" content="g{n}">' for n in range(20))
    assert len(page_facts(many)["generator"]) == MAX_GENERATORS
    long = f'<meta name="generator" content="{"x" * 500}">'
    assert len(page_facts(long)["generator"][0]) == 100
    assert page_facts('<meta name="generator" content="">')["generator"] == []
    assert page_facts('<meta name="description" content="WordPress">')["generator"] == []


# ------------------------------------------------------------------------------ resources


def test_a_script_of_the_site_is_a_path_and_an_external_one_is_a_host_and_a_path() -> None:
    html = (
        '<script src="/wp-includes/js/jquery/jquery.min.js?ver=3.7.1&amp;x=secret"></script>'
        '<script src="https://WWW.GoogleTagManager.com:443/gtm.js?id=GTM-ABC123"></script>'
        '<script src="//cdn.example.net/a.js"></script>'
        '<script src="relative/b.js"></script>'
    )
    assert resources(html) == [
        {
            "kind": "script",
            "host": None,
            "path": "/wp-includes/js/jquery/jquery.min.js",
            "version": "3.7.1",
        },
        {"kind": "script", "host": "www.googletagmanager.com", "path": "/gtm.js", "version": None},
        {"kind": "script", "host": "cdn.example.net", "path": "/a.js", "version": None},
        {"kind": "script", "host": None, "path": "relative/b.js", "version": None},
    ]


def test_query_strings_are_dropped_except_a_version() -> None:
    """Other parameters may carry tokens; a key in a URL is not stored."""
    html = '<script src="https://maps.googleapis.com/maps/api/js?key=AIzaSECRET&v=3.55"></script>'
    (found,) = resources(html)
    assert found["version"] == "3.55" and "AIza" not in json.dumps(found)
    odd = '<script src="/a.js?ver=<script>alert(1)</script>"></script>'
    assert resources(odd)[0]["version"] is None  # only a plain version value is kept


@pytest.mark.parametrize(
    "src",
    [
        "javascript:alert(1)",
        "data:text/javascript,1",
        "mailto:a@example.com",
        "",
        "   ",
        "http://[::1",
    ],
)
def test_what_is_not_a_web_resource_is_ignored(src: str) -> None:
    assert resources(f'<script src="{src}"></script><iframe src="{src}"></iframe>') == []


def test_only_the_link_relations_that_load_something_count() -> None:
    html = (
        '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Inter">'
        '<link rel="preconnect" href="https://fonts.gstatic.com">'
        '<link rel="dns-prefetch" href="//cdn.example.net">'
        '<link rel="canonical" href="https://www.example.com/">'
        '<link rel="alternate" href="/feed.xml">'
        '<link rel="shortcut icon" href="/favicon.ico">'
    )
    found = {(r["kind"], r["host"], r["path"]) for r in resources(html)}
    assert found == {
        ("link", "fonts.googleapis.com", "/css2"),
        ("link", "fonts.gstatic.com", ""),
        ("link", "cdn.example.net", ""),
        ("link", None, "/favicon.ico"),
    }


def test_frames_count_and_images_and_forms_only_when_they_are_external() -> None:
    html = (
        '<iframe src="https://www.youtube.com/embed/abc"></iframe>'
        '<iframe src="/own/frame.html"></iframe>'
        '<img src="/logo.png"><img src="https://px.example.net/t.gif?x=1">'
        '<form action="/search"></form><form action="https://forms.hsforms.com/submit"></form>'
    )
    found = {(r["kind"], r["host"], r["path"]) for r in resources(html)}
    assert found == {
        ("iframe", "www.youtube.com", "/embed/abc"),
        ("iframe", None, "/own/frame.html"),
        ("img", "px.example.net", "/t.gif"),
        ("form", "forms.hsforms.com", "/submit"),
    }


def test_the_same_resource_is_listed_once() -> None:
    html = '<script src="/a.js"></script>' * 5 + '<script src="/a.js?ver=2"></script>'
    assert len(resources(html)) == 1


# ------------------------------------------------------------------------------ inline scripts


def test_inline_scripts_name_the_interfaces_they_call_and_the_hosts_they_load_from() -> None:
    facts = page_facts(GTM_SNIPPET)
    assert "gtm" in facts["markers"]  # the Tag Manager snippet is recognised by what it sets
    assert facts["inline_hosts"] == ["www.googletagmanager.com"]
    assert page_facts(
        '<script>window.dataLayer = window.dataLayer || [];function gtag(){}gtag("js", 1);</script>'
    )["markers"] == ["dataLayer", "gtag"]
    assert (
        "fbq"
        in page_facts("<script>fbq('init', '123'); fbq('track', 'PageView');</script>")["markers"]
    )


def test_scripts_that_are_not_javascript_are_not_read_for_hosts() -> None:
    """JSON-LD names schema.org and a template names whatever it templates: not loads."""
    html = (
        '<script type="application/ld+json">{"@context": "https://schema.org/"}</script>'
        '<script type="text/template"><img src="https://tracker.example.net/x/"></script>'
    )
    facts = page_facts(html)
    assert facts["inline_hosts"] == [] and facts["markers"] == []


def test_inline_hosts_are_limited() -> None:
    script = (
        "<script>" + " ".join(f"'https://h{n}.example.net/x'" for n in range(100)) + "</script>"
    )
    assert len(page_facts(script)["inline_hosts"]) == MAX_INLINE_HOSTS


# ------------------------------------------------------------------------------ bounds


def test_a_page_with_more_resources_than_the_limit_is_cut_and_says_so() -> None:
    html = "".join(f'<script src="/s{n}.js"></script>' for n in range(MAX_RESOURCES + 50))
    facts = page_facts(html)
    assert len(facts["resources"]) == MAX_RESOURCES and facts["truncated"] is True


def test_a_page_with_more_tags_than_the_limit_is_cut_and_says_so() -> None:
    html = "<p>x</p>" * (MAX_TAGS * 2) + '<script src="/late.js"></script>'
    facts = page_facts(html)
    assert facts["truncated"] is True and facts["tags"] == MAX_TAGS
    assert facts["resources"] == []  # what came after the limit was not read


def test_hostile_markup_never_raises_and_stays_bounded() -> None:
    hostile = [
        "<" * 200_000,
        "<script src=" + "a" * 100_000 + ">",
        '<meta name="generator" content="' + "x" * 100_000,
        "<a " * 50_000,
        "<script>" + "//" * 100_000,
        "\x00\x01<script src='/\x00.js'></script>",
        "<<<>>>&#xFFFFFFFF;&bogus;<script src=",
        "<div>" * 100_000,
    ]
    for html in hostile:
        facts = page_facts(html)
        assert len(facts["resources"]) <= MAX_RESOURCES
        assert len(json.dumps(facts)) < 100_000


def test_an_empty_or_non_html_text_gives_nothing() -> None:
    for text in ("", "plain text", '{"json": true}'):
        facts = page_facts(text)
        assert facts["generator"] == [] and facts["resources"] == [] and facts["markers"] == []


def test_the_text_of_the_page_is_never_kept() -> None:
    html = (
        "<html><body><p>SECRET-PAGE-TEXT</p>"
        "<script>var token = 'SECRET-TOKEN'; gtag('x');</script></body></html>"
    )
    assert "SECRET" not in json.dumps(page_facts(html))
