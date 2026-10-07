"""Hosted services whose names a stranger can claim when an alias to them is left dangling.

A customer points ``shop.vendor.example`` at a hosted service with a CNAME (``vendor.github.io``,
``vendor.azurewebsites.net``). When the resource behind it is deleted but the DNS record stays,
anybody may create a resource of the same name at the service and then serve content on the
vendor's host name. Each entry says which CNAME targets belong to a service and how an unclaimed
name shows itself:

- ``dns``: the target does not exist at all (the DNS check says so), and the service lets anyone
  register that name;
- ``page``: the target exists (it is the service's shared edge), and the service answers a request
  for the host with a page of its own that says "nothing here": the signatures below, with the
  HTTP status the page comes with.

``claim`` is how far the claim is open: ``open`` when anyone may register the name, ``conditional``
when the service checks something first (an account, a verified domain) so that it depends on the
service and the vendor's settings.

Source and changes. The services and the "unclaimed" pages are adapted from the fingerprints of
can-i-take-over-xyz (EdOverflow and contributors, https://github.com/EdOverflow/can-i-take-over-xyz,
licensed CC BY 4.0, https://creativecommons.org/licenses/by/4.0/; ``fingerprints.json`` at commit
5bd4e12 of 2025-02-08). Changes made here: only services that were seen to answer an unclaimed,
random name in the way written below on 2026-10-07 are kept, the ones the source lists as "Not
vulnerable" are left out, the CNAME targets are written out (the source leaves most of them empty)
and the signatures are the texts the services show today (several of the source's texts are
outdated or carry markup). A service that answers only over HTTPS with a certificate that does
not match (Ghost, Help Scout, Webflow's ``proxy-ssl``) is not listed: the egress gate never turns
certificate verification off, so its page cannot be read.

To add a service: ask it for a name nobody can own (``wdd-<random>.<its domain>``, and its edge
with an unknown ``Host`` header, over plain HTTP), copy what it says, give the entry the status it
came with, and let ``tests/checks/test_takeover_live.py`` confirm it (``pytest -m live``).
"""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Literal

SOURCE = "can-i-take-over-xyz"  # the ``source`` of every result; the report credits it by this
SOURCE_URL = "https://github.com/EdOverflow/can-i-take-over-xyz"
LICENCE_URL = "https://creativecommons.org/licenses/by/4.0/"
CHECKED_ON = "2026-10-07"  # when the entries were last seen to behave as written

Method = Literal["page", "dns"]
Claim = Literal["open", "conditional"]


_QUOTES = str.maketrans(
    {
        "\N{LEFT SINGLE QUOTATION MARK}": "'",
        "\N{RIGHT SINGLE QUOTATION MARK}": "'",
        "\N{LEFT DOUBLE QUOTATION MARK}": '"',
        "\N{RIGHT DOUBLE QUOTATION MARK}": '"',
    }
)


def normalise(text: str) -> str:
    """Text as signatures are compared: entities resolved, typographic quotes made plain, case
    folded, white space collapsed."""
    return " ".join(html.unescape(text).translate(_QUOTES).casefold().split())


@dataclass(frozen=True)
class Service:
    key: str
    name: str
    how: Method
    claim: Claim
    suffixes: tuple[str, ...] = ()  # a CNAME target equal to one, or below one, belongs here
    pattern: re.Pattern[str] | None = None  # for the targets suffixes cannot describe
    signatures: tuple[str, ...] = ()  # ``page``: any of them in the body shows an unclaimed name
    statuses: tuple[int, ...] = (404,)  # ``page``: the status that page comes with

    def matches(self, target: str) -> bool:
        name = target.lower().rstrip(".")
        if self.pattern is not None and self.pattern.search(name):
            return True
        return any(name == suffix or name.endswith("." + suffix) for suffix in self.suffixes)


# S3: ``bucket.s3.amazonaws.com``, ``bucket.s3.eu-west-1.amazonaws.com``,
# ``bucket.s3-eu-west-1.amazonaws.com`` and the website endpoints ``bucket.s3-website-us-east-1``,
# ``bucket.s3-website.eu-west-1``. Other ``amazonaws.com`` names (EC2, load balancers) are not S3.
_S3 = re.compile(r"(^|\.)s3(-website)?([.-][a-z0-9.-]+)?\.amazonaws\.com$")

# The Azure namespaces below were all seen to answer NXDOMAIN for a random name on 2026-10-07; a
# name that does not exist can be registered by whoever asks first.
_AZURE = (
    "azurewebsites.net",
    "cloudapp.net",
    "cloudapp.azure.com",
    "trafficmanager.net",
    "blob.core.windows.net",
    "azureedge.net",
    "azure-api.net",
    "azurecontainer.io",
)

SERVICES: tuple[Service, ...] = (
    Service(
        "github_pages",
        "GitHub Pages",
        "page",
        "conditional",
        suffixes=("github.io",),
        signatures=("There isn't a GitHub Pages site here.",),
    ),
    Service(
        "heroku",
        "Heroku",
        "page",
        "conditional",
        # herokudns.com is the target Heroku hands out for custom domains today; a random name
        # under it does not resolve, so only herokuapp.com was probed (the same router answers).
        suffixes=("herokuapp.com", "herokudns.com"),
        # The page is an iframe around Heroku's own error page; its title is the only text.
        signatures=("<title>No such app</title>", "herokucdn.com/error-pages/no-such-app"),
    ),
    Service(
        "aws_s3",
        "Amazon S3",
        "page",
        "open",
        pattern=_S3,
        signatures=("The specified bucket does not exist",),
    ),
    Service(
        "netlify",
        "Netlify",
        "page",
        "conditional",
        suffixes=("netlify.app", "netlify.com"),
        # The plain text page is what a client without a preference gets, the HTML page what a
        # browser gets (the check asks like a browser).
        signatures=("Not Found - Request ID:", "entered a URL that doesn't exist on Netlify"),
    ),
    Service(
        "vercel",
        "Vercel",
        "page",
        "conditional",
        suffixes=("vercel.app", "vercel-dns.com"),
        signatures=("DEPLOYMENT_NOT_FOUND",),
    ),
    Service(
        "surge",
        "Surge",
        "page",
        "open",
        suffixes=("surge.sh",),
        signatures=("project not found",),
    ),
    Service(
        "pantheon",
        "Pantheon",
        "page",
        "open",
        suffixes=("pantheonsite.io", "pantheon.io"),
        signatures=("404 - Unknown site",),
    ),
    Service(
        "tilda",
        "Tilda",
        "page",
        "conditional",
        suffixes=("tilda.ws",),
        signatures=("Please go to the site settings and put the domain name in the Domain tab",),
    ),
    Service("azure", "Microsoft Azure", "dns", "open", suffixes=_AZURE),
    Service(
        "aws_elastic_beanstalk",
        "AWS Elastic Beanstalk",
        "dns",
        "open",
        suffixes=("elasticbeanstalk.com",),
    ),
    Service("discourse", "Discourse", "dns", "open", suffixes=("trydiscourse.com",)),
)

BY_KEY = {service.key: service for service in SERVICES}


def services_for(target: str) -> list[Service]:
    """The services a CNAME target belongs to (normally none or one)."""
    return [service for service in SERVICES if service.matches(target)]
