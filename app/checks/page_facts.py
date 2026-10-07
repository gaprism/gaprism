"""What a home page says about the software and services behind it, read from its HTML.

The HTML comes from the assessed host, so it is untrusted and the reading is bounded: at most
``MAX_TAGS`` start tags are looked at, every value is cut short, only a fixed set of facts is kept
and the page's text is never stored. The facts are what is needed to recognise technologies and
third parties (``app/checks/tech.py``):

- ``generator``: the values of ``<meta name="generator">``;
- ``resources``: where scripts, style sheets, frames, images and forms come from, as the host (or
  ``None`` for the site's own files) and the path; of the query string only a version parameter
  (``ver``, ``v``, ``version``) is kept, because other parameters may carry tokens;
- ``markers``: which well-known script interfaces inline scripts use (``gtag``, ``fbq``, ...), and
  the hosts that inline scripts load code from (a tag manager's loader is an inline snippet).

Nothing is fetched: this reads the page the HTTP check already has.
"""

from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any
from urllib.parse import urlsplit

MAX_TAGS = 6000  # start tags looked at; a page with more is cut and says so
MAX_RESOURCES = 120
MAX_GENERATORS = 5
MAX_INLINE_HOSTS = 30
MAX_INLINE_CHARS = 60_000  # inline script text looked at, in all
MAX_PATH = 200
MAX_HOST = 253
VERSION_PARAMETERS = ("ver", "v", "version")
SCRIPT_TYPES = ("", "text/javascript", "application/javascript", "module", "text/ecmascript")
LINK_RELATIONS = (
    "stylesheet",
    "preload",
    "prefetch",
    "preconnect",
    "dns-prefetch",
    "modulepreload",
    "icon",
)

# Interfaces that inline scripts of well-known services call; only the name is kept.
MARKERS = {
    "gtag": re.compile(r"\bgtag\s*\("),
    "gtm": re.compile(r"\bgtm\.start\b"),
    "dataLayer": re.compile(r"\bdataLayer\s*(?:=|\.push)"),
    "ga": re.compile(r"\bga\s*\(\s*['\"](?:create|send)['\"]"),
    "fbq": re.compile(r"\bfbq\s*\("),
    "_paq": re.compile(r"\b_paq\s*(?:=|\.push)"),
    "_gaq": re.compile(r"\b_gaq\s*(?:=|\.push)"),
    "hj": re.compile(r"\bhj\s*\(\s*['\"]"),
    "clarity": re.compile(r"\bclarity\s*\(\s*['\"]"),
    "Shopify": re.compile(r"\bShopify\s*\.\s*(?:theme|shop|locale)"),
    "wixBiSession": re.compile(r"\bwixBiSession\b"),
    "Intercom": re.compile(r"\bIntercom\s*\(\s*['\"]"),
    "drift": re.compile(r"\bdrift\s*\.\s*(?:SNIPPET_VERSION|load)"),
    "Sentry": re.compile(r"\bSentry\s*\.\s*init\s*\("),
    "mixpanel": re.compile(r"\bmixpanel\s*\.\s*(?:init|track)"),
    "analytics": re.compile(r"\banalytics\s*\.\s*(?:load|page)\s*\("),
    "twq": re.compile(r"\btwq\s*\(\s*['\"]"),
    "lintrk": re.compile(r"\blintrk\s*\("),
    "ttq": re.compile(r"\bttq\s*\.\s*(?:load|page)"),
}
_INLINE_HOST = re.compile(
    r"(?:https?:)?//((?:[a-z0-9-]{1,63}\.)+[a-z]{2,24})(?::\d+)?/", re.IGNORECASE
)


class _ReadingStoppedError(Exception):
    """Raised inside the parser to end the reading early (the page is bigger than the bounds)."""


def _host_and_path(value: str) -> tuple[str | None, str, str | None] | None:
    """(host, path, version) of a URL found in a page; ``host`` is ``None`` for the site's own
    files. ``None`` for what is not a web resource (``data:``, ``javascript:``, an empty value)."""
    value = value.strip()
    if not value or len(value) > 2000:
        return None
    try:
        parts = urlsplit(value)
    except ValueError:
        return None
    if parts.scheme and parts.scheme.lower() not in ("http", "https"):
        return None
    host: str | None = None
    if parts.netloc:
        host = (parts.hostname or "").lower()[:MAX_HOST] or None
        if host is None:
            return None
    version: str | None = None
    for part in parts.query.split("&")[:12]:
        key, _, found = part.partition("=")
        if key.lower() in VERSION_PARAMETERS and re.fullmatch(r"[\w.\-]{1,24}", found):
            version = found
            break
    return host, parts.path[:MAX_PATH], version


class _Reader(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.tags = 0
        self.generator: list[str] = []
        self.resources: list[dict[str, Any]] = []
        self._seen: set[tuple[str, str | None, str]] = set()
        self.markers: set[str] = set()
        self.inline_hosts: list[str] = []
        self._inline: list[str] | None = None
        self._inline_chars = 0
        self.truncated = False

    def _resource(self, kind: str, value: str, external_only: bool = False) -> None:
        found = _host_and_path(value)
        if found is None:
            return
        host, path, version = found
        if external_only and host is None:
            return
        key = (kind, host, path)
        if key in self._seen or len(self.resources) >= MAX_RESOURCES:
            if len(self.resources) >= MAX_RESOURCES:
                self.truncated = True
            return
        self._seen.add(key)
        self.resources.append({"kind": kind, "host": host, "path": path, "version": version})

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        self.tags += 1
        if self.tags > MAX_TAGS:
            self.truncated = True
            raise _ReadingStoppedError
        attributes = {name.lower(): value or "" for name, value in attrs}
        if tag == "meta":
            if attributes.get("name", "").strip().lower() == "generator":
                text = " ".join(attributes.get("content", "").split())[:100]
                if text and len(self.generator) < MAX_GENERATORS and text not in self.generator:
                    self.generator.append(text)
        elif tag == "script":
            if attributes.get("src"):
                self._resource("script", attributes["src"])
            elif attributes.get("type", "").strip().lower() in SCRIPT_TYPES:
                self._inline = []  # not JSON-LD or a template: those only name hosts
        elif tag == "link":
            relations = attributes.get("rel", "").lower().split()
            if any(relation in LINK_RELATIONS for relation in relations):
                self._resource("link", attributes.get("href", ""))
        elif tag == "iframe":
            self._resource("iframe", attributes.get("src", ""))
        elif tag == "img":
            self._resource("img", attributes.get("src", ""), external_only=True)
        elif tag == "form":
            self._resource("form", attributes.get("action", ""), external_only=True)

    def handle_data(self, data: str) -> None:
        if self._inline is not None and self._inline_chars < MAX_INLINE_CHARS:
            chunk = data[: MAX_INLINE_CHARS - self._inline_chars]
            self._inline.append(chunk)
            self._inline_chars += len(chunk)

    def handle_endtag(self, tag: str) -> None:
        if tag == "script" and self._inline is not None:
            text = "".join(self._inline)
            self._inline = None
            for name, pattern in MARKERS.items():
                if pattern.search(text):
                    self.markers.add(name)
            for found in _INLINE_HOST.finditer(text):
                host = found.group(1).lower()
                if host not in self.inline_hosts and len(self.inline_hosts) < MAX_INLINE_HOSTS:
                    self.inline_hosts.append(host)


def page_facts(html: str) -> dict[str, Any]:
    """The bounded facts of one page (see the module docstring). Never raises: a page that cannot
    be read as HTML gives what was read until then."""
    reader = _Reader()
    try:
        reader.feed(html)
        reader.close()
    except _ReadingStoppedError:
        pass
    except Exception:  # hostile markup must never fail a check
        reader.truncated = True
    return {
        "generator": reader.generator,
        "resources": reader.resources,
        "markers": sorted(reader.markers),
        "inline_hosts": reader.inline_hosts,
        "tags": min(reader.tags, MAX_TAGS),
        "truncated": reader.truncated,
    }
