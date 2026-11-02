"""What leaves the installation: the code, the documentation and the pages say the same thing.

The application promises that it does not phone home. It sends no telemetry, no crash reports and
no update checks, and it checks no licence; every request goes to a scan target or to a data source
that docs/deploy.md ("What leaves your network") lists; and its pages load nothing from outside the
installation. These tests keep that true while the code changes:

- every host the code names in a URL, and every resolver address, is in that section of the
  documentation, or is on a short list of hosts that are only links or credits (with the reason);
- the Content-Security-Policy allows nothing but the installation's own origin, and the templates,
  stylesheets and first-party scripts load nothing from another one;
- no telemetry or crash-reporting package is a dependency or is imported.

They are tripwires, not proofs. A static scan does not see a destination that is put together at run
time from parts, and it cannot read what a vendored library does (htmx is held to the policy by the
browser instead). What it does is make a new destination a visible change: the build fails until
the person who adds it has said, in the documentation, who receives what and why, which is the
conversation the promise needs.
"""

from __future__ import annotations

import ast
import re
import tomllib
from html.parser import HTMLParser
from pathlib import Path

import pytest

from app.web import CONTENT_SECURITY_POLICY
from tests.helpers import PROJECT_ROOT
from tests.test_dependencies import RUNTIME_CODE, top_level_imports

REQUEST_CODE = ("app", "runner")  # where the requests are made

# Hosts the code names that are only a link or a credit: nothing is sent there; a person may click.
LINKS_ONLY = {
    "creativecommons.org": "the licence link in the credit of the takeover ruleset",
    "db-ip.com": "the credit for the IP location data",
    "developer.mozilla.org": "a link to the Observatory's details; the page is never requested",
    "github.com": "links to credited projects, and the project address in the User-Agent",
    "www.first.org": "the credit for the EPSS scores",
    "www.shodan.io": "the credit for Shodan in the export",
}

# Plain IPv4 addresses in the code that are not destinations of the application, and why not. (The
# egress gate's address ranges are written with a prefix length, so they are not plain addresses.)
NOT_DESTINATIONS = {
    "0.0.0.0": "the answer a security resolver gives for a name it blocks",
    "1.3.101.112": "the object identifier of Ed25519, not an address",
    "1.3.101.113": "the object identifier of Ed448, not an address",
}

# Packages and modules whose job is to report what an installation does to somebody else.
TELEMETRY_PACKAGES = set(
    """airbrake amplitude-analytics analytics-python appsignal bugsnag datadog ddtrace elastic-apm
    fullstory honeybadger launchdarkly-server-sdk logfire mixpanel newrelic opentelemetry-api
    opentelemetry-distro opentelemetry-sdk pendo posthog raven rollbar scout-apm
    segment-analytics-python sentry-sdk statsig""".split()
)
TELEMETRY_MODULES = set(
    """airbrake amplitude analytics appsignal bugsnag datadog ddtrace elasticapm fullstory
    honeybadger ldclient logfire mixpanel newrelic opentelemetry pendo posthog raven rollbar
    scout_apm segment sentry_sdk statsig""".split()
)

URL = re.compile(r"https?://([A-Za-z0-9.-]+)")
IPV4 = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d./])")
SCHEME = r"(?:[a-z][a-z0-9+.-]*:)?//"  # http://, https://, //, ws://, ...
REMOTE = re.compile(rf"(?:^|[\s,]){SCHEME}", re.IGNORECASE)
REMOTE_CSS = re.compile(rf"""(?:@import\s+|url\()\s*["']?{SCHEME}""", re.IGNORECASE)
NETWORK_IN_JS = re.compile(
    r"\b(?:fetch|XMLHttpRequest|sendBeacon|WebSocket|EventSource|importScripts)\b"
    r"|import\s*\(|https?://"
)

# What a page loads (or sends a form to) when it is rendered; an <a href> is not on this list: a
# click is the visitor's own.
RESOURCE_ATTRIBUTES = {
    "script": {"src"},
    "link": {"href", "imagesrcset"},
    "img": {"src", "srcset"},
    "iframe": {"src"},
    "frame": {"src"},
    "source": {"src", "srcset"},
    "video": {"src", "poster"},
    "audio": {"src"},
    "track": {"src"},
    "embed": {"src"},
    "object": {"data"},
    "input": {"src"},
    "base": {"href"},
    "form": {"action"},
}
HTMX_REQUESTS = {"hx-get", "hx-post", "hx-put", "hx-patch", "hx-delete"}


# ------------------------------------------------------------------------------ the scanners


def code_strings(source: str) -> list[str]:
    """The string constants of a module, without its docstrings (which only talk)."""
    tree = ast.parse(source)
    docstrings = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.ClassDef | ast.FunctionDef | ast.AsyncFunctionDef):
            first = node.body[0] if node.body else None
            if isinstance(first, ast.Expr) and isinstance(first.value, ast.Constant):
                docstrings.add(id(first.value))
    return [
        node.value
        for node in ast.walk(tree)
        if isinstance(node, ast.Constant)
        and isinstance(node.value, str)
        and id(node) not in docstrings
    ]


def strings_of(folders: tuple[str, ...]) -> dict[str, list[str]]:
    """The string constants of every module of ``folders``, by file."""
    found = {}
    for folder in folders:
        for path in sorted((PROJECT_ROOT / folder).rglob("*.py")):
            found[path.relative_to(PROJECT_ROOT).as_posix()] = code_strings(
                path.read_text(encoding="utf-8-sig")
            )
    return found


def url_hosts(strings: dict[str, list[str]]) -> dict[str, set[str]]:
    """The host names in URLs, with the files that name them. A name without a dot is a template
    (``https://{host}/``) or a placeholder, not a destination."""
    hosts: dict[str, set[str]] = {}
    for file, texts in strings.items():
        for text in texts:
            for found in URL.finditer(text):
                host = found.group(1).lower().rstrip(".")
                if "." in host:
                    hosts.setdefault(host, set()).add(file)
    return hosts


def addresses(strings: dict[str, list[str]]) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for file, texts in strings.items():
        for text in texts:
            for match in IPV4.finditer(text):
                found.setdefault(match.group(0), set()).add(file)
    return found


def mentioned(section: str, token: str) -> bool:
    """Is ``token`` (a host name or an address) in the text as a word of its own? ``db-ip.com`` is
    not mentioned by ``download.db-ip.com``."""
    return re.search(rf"(?<![A-Za-z0-9.-]){re.escape(token)}(?![A-Za-z0-9-])", section) is not None


def leaves_section() -> str:
    text = (PROJECT_ROOT / "docs" / "deploy.md").read_text(encoding="utf-8")
    start = text.index("## What leaves your network")
    return text[start : text.index("\n## ", start + 1)]


class ResourceFinder(HTMLParser):
    """The places where a page loads something (or sends a form) from another origin."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.found: list[tuple[str, str, str]] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        for name, value in attrs:
            watched = name in RESOURCE_ATTRIBUTES.get(tag, set()) or name in HTMX_REQUESTS
            if watched and value and REMOTE.search(value):
                self.found.append((tag, name, value.strip()[:80]))


def remote_resources(html: str) -> list[tuple[str, str, str]]:
    finder = ResourceFinder()
    finder.feed(html)
    return finder.found


# ------------------------------------------------------------------------------ hosts and addresses


def test_every_host_the_code_names_is_documented_or_only_a_link() -> None:
    section = leaves_section()
    hosts = url_hosts(strings_of(REQUEST_CODE))
    undocumented = {
        host: sorted(files)
        for host, files in hosts.items()
        if host not in LINKS_ONLY and not mentioned(section, host)
    }
    assert not undocumented, (
        f"the code names hosts that docs/deploy.md ('What leaves your network') does not: "
        f"{undocumented}. If the application sends something there, say who receives what, "
        "when, and which setting changes it, and add it to app/service/disclosure.py. If it is "
        "only a link or a credit, add it to LINKS_ONLY with the reason."
    )


def test_the_hosts_that_are_only_links_are_still_named_in_the_code() -> None:
    hosts = url_hosts(strings_of(REQUEST_CODE))
    stale = sorted(set(LINKS_ONLY) - set(hosts))
    assert not stale, f"no longer named in the code (remove them from LINKS_ONLY): {stale}"
    redundant = sorted(host for host in LINKS_ONLY if mentioned(leaves_section(), host))
    # A link-only host that the section lists now is a destination: say so in one place only.
    assert not redundant or redundant == ["github.com"], (
        f"documented as a destination too: {redundant}"
    )


def test_every_address_in_the_code_is_a_documented_resolver_or_not_a_destination() -> None:
    section = leaves_section()
    found = addresses(strings_of(REQUEST_CODE))
    unexplained = {
        address: sorted(files)
        for address, files in found.items()
        if address not in NOT_DESTINATIONS and not mentioned(section, address)
    }
    assert not unexplained, (
        f"addresses in the code that docs/deploy.md does not list: {unexplained}. A resolver or "
        "server the application talks to goes into 'What leaves your network'; anything else "
        "goes into NOT_DESTINATIONS with the reason."
    )
    assert {"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.1.1.2"} <= set(found)  # the scan really finds them


def test_the_addresses_that_are_not_destinations_are_still_in_the_code() -> None:
    stale = sorted(set(NOT_DESTINATIONS) - set(addresses(strings_of(REQUEST_CODE))))
    assert not stale, f"no longer in the code (remove them from NOT_DESTINATIONS): {stale}"


# ------------------------------------------------------------------------------ the pages


def test_the_content_security_policy_allows_only_the_installations_own_origin() -> None:
    directives = {
        words[0]: words[1:]
        for words in (part.split() for part in CONTENT_SECURITY_POLICY.split(";"))
        if words
    }
    for name in ("default-src", "script-src", "style-src", "font-src", "connect-src"):
        assert directives[name] == ["'self'"], f"{name}: {directives[name]}"
    assert directives["img-src"] == ["'self'", "data:"]
    assert directives["object-src"] == ["'none'"] and directives["frame-ancestors"] == ["'none'"]
    assert directives["form-action"] == ["'self'"] and directives["base-uri"] == ["'self'"]
    sources = {source for values in directives.values() for source in values}
    assert sources <= {"'self'", "'none'", "data:"}, f"a source of another origin: {sources}"


def test_no_template_loads_or_sends_anything_to_another_origin() -> None:
    offenders = {}
    for path in sorted((PROJECT_ROOT / "app" / "templates").rglob("*.html")):
        found = remote_resources(path.read_text(encoding="utf-8"))
        if found:
            offenders[path.relative_to(PROJECT_ROOT).as_posix()] = found
    assert not offenders, (
        f"templates that load or send to another origin: {offenders}. Links (<a href>) to other "
        "sites are fine; scripts, styles, images, fonts, frames and forms are served from here."
    )


def test_no_stylesheet_loads_anything_from_another_origin() -> None:
    offenders = {}
    for folder in ("assets", "app/static/css"):
        for path in sorted((PROJECT_ROOT / folder).glob("*.css")):
            found = REMOTE_CSS.findall(path.read_text(encoding="utf-8"))
            if found:
                offenders[path.relative_to(PROJECT_ROOT).as_posix()] = found[:3]
    assert not offenders, f"stylesheets that import or load from another origin: {offenders}"


def test_the_scripts_are_the_ones_that_were_looked_at_and_ours_make_no_requests() -> None:
    # htmx.min.js is the library; report.js is the report's print button; nav.js is the sidebar's
    # collapse button, which keeps its choice in the browser's own storage and talks to no one.
    scripts = sorted(path.name for path in (PROJECT_ROOT / "app" / "static" / "js").glob("*.js"))
    assert scripts == ["htmx.min.js", "nav.js", "report.js"], (
        f"a script that was not reviewed for network calls: {scripts}. Read it, and say here "
        "what it does."
    )
    for name in ("nav.js", "report.js"):
        own = (PROJECT_ROOT / "app" / "static" / "js" / name).read_text(encoding="utf-8")
        assert not NETWORK_IN_JS.search(own), f"{name} reaches for the network"


# ------------------------------------------------------------------------------ no telemetry


def locked_packages() -> set[str]:
    lock = tomllib.loads((PROJECT_ROOT / "uv.lock").read_text(encoding="utf-8"))
    return {re.sub(r"[-_.]+", "-", package["name"]).lower() for package in lock["package"]}


def test_no_telemetry_or_crash_reporting_package_is_installed_with_the_application() -> None:
    present = sorted(locked_packages() & TELEMETRY_PACKAGES)
    assert not present, (
        f"in uv.lock: {present}. The application does not phone home: no telemetry, no crash "
        "reports, no update checks, no licence checks."
    )


def test_no_telemetry_or_crash_reporting_module_is_imported() -> None:
    imported = {}
    for folder in RUNTIME_CODE:
        for path in sorted((PROJECT_ROOT / folder).rglob("*.py")):
            hit = top_level_imports(path) & TELEMETRY_MODULES
            if hit:
                imported[path.relative_to(PROJECT_ROOT).as_posix()] = sorted(hit)
    assert not imported, f"imports that report to somebody else: {imported}"


# ------------------------------------------------------------------------------ the scanners work


def test_the_scanners_find_what_they_are_meant_to_find() -> None:
    strings = code_strings(
        '"""A docstring that names https://docs.example.org/page."""\n'
        'URL = "https://api.example.net/v1/lookup"\n'
        'TEMPLATE = f"https://{host}/path"\n'
        'RESOLVER = "9.9.9.9"\n'
        'RANGE = "10.0.0.0/8"\n'
    )
    assert url_hosts({"x.py": strings}) == {
        "api.example.net": {"x.py"}
    }  # not the docstring, not a template
    assert set(addresses({"x.py": strings})) == {"9.9.9.9"}  # not a range

    assert mentioned("send to `download.db-ip.com`.", "download.db-ip.com")
    assert not mentioned("send to `download.db-ip.com`.", "db-ip.com")
    assert mentioned("the host db-ip.com, and more", "db-ip.com")


@pytest.mark.parametrize(
    "html",
    [
        '<script src="https://cdn.example.net/a.js"></script>',
        '<script src="//cdn.example.net/a.js"></script>',
        '<link rel="stylesheet" href="http://fonts.example.net/x.css">',
        '<img src="https://img.example.net/x.png">',
        '<img srcset="a.png 1x, https://img.example.net/b.png 2x">',
        '<iframe src="https://frame.example.net/"></iframe>',
        '<form action="https://post.example.net/" method="post"></form>',
        '<div hx-get="https://api.example.net/x"></div>',
        '<base href="https://other.example.net/">',
    ],
)
def test_a_resource_from_another_origin_is_found(html: str) -> None:
    assert remote_resources(html), html


@pytest.mark.parametrize(
    "html",
    [
        '<a href="https://www.example.org/docs">a link is the visitor\'s own click</a>',
        "<script src=\"{{ url_for('static', filename='js/htmx.min.js') }}\" defer></script>",
        '<link rel="stylesheet" href="/static/css/app.css">',
        '<img src="data:image/png;base64,AAAA">',
        '<div hx-get="/assessments/1/scan-panel"></div>',
        '<form action="/auth/login" method="post"></form>',
    ],
)
def test_what_is_served_from_here_or_only_linked_is_not_flagged(html: str) -> None:
    assert not remote_resources(html), html


def test_the_stylesheet_scan_flags_imports_but_not_inline_data() -> None:
    assert REMOTE_CSS.search("@import url(https://fonts.example.net/x.css);")
    assert REMOTE_CSS.search('@font-face { src: url("//fonts.example.net/x.woff2"); }')
    assert not REMOTE_CSS.search('.a { background: url("data:image/svg+xml,%3Csvg xmlns=...") }')
    assert not REMOTE_CSS.search("@font-face { src: url(/static/fonts/Inter-Regular.woff2); }")


def test_the_script_scan_flags_network_calls() -> None:
    for code in ("fetch('/x')", "new XMLHttpRequest()", "navigator.sendBeacon(u)", "import('x')"):
        assert NETWORK_IN_JS.search(code), code
    assert not NETWORK_IN_JS.search(
        'button.addEventListener("click", function () { window.print(); });'
    )


def test_the_project_files_the_scanners_read_exist() -> None:
    assert Path(PROJECT_ROOT / "docs" / "deploy.md").is_file()
    assert any((PROJECT_ROOT / "app" / "templates").rglob("*.html"))
    assert any((PROJECT_ROOT / "app" / "static" / "css").glob("*.css"))
