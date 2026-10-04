"""Which network an address belongs to: a small, advisory list of CDNs and hosting providers.

It exists for one question: is this address an *edge* (CDN or anycast) whose geolocation shows
the point of presence rather than the data centre? Such an address must not raise a location
finding with full confidence. The list is deliberately short and conservative; an address that
is not listed is simply unclassified, never "not a CDN".

Known gap: Amazon CloudFront shares its AS numbers with EC2, so the AS alone cannot tell them
apart. A ``cloudfront.net`` name in the CNAME chain or reverse DNS does.
"""

from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass

KINDS = ("cdn", "cloud", "hosting")


@dataclass(frozen=True)
class NetworkHint:
    name: str
    kind: str  # cdn | cloud | hosting
    edge: bool  # anycast / point-of-presence network: the location is not the data centre

    def to_data(self) -> dict[str, object]:
        return {"name": self.name, "kind": self.kind, "edge": self.edge}


def _cdn(name: str) -> NetworkHint:
    return NetworkHint(name, "cdn", True)


CLOUDFLARE = _cdn("Cloudflare")
FASTLY = _cdn("Fastly")
AKAMAI = _cdn("Akamai")
EDGIO = _cdn("Edgio (Edgecast, Limelight)")
IMPERVA = _cdn("Imperva")
SUCURI = _cdn("Sucuri")
STACKPATH = _cdn("StackPath")
CDN77 = _cdn("CDN77")
BUNNY = _cdn("Bunny CDN")
GCORE = _cdn("Gcore")
CDNETWORKS = _cdn("CDNetworks")
CLOUDFRONT = _cdn("Amazon CloudFront")
AZURE_CDN = _cdn("Azure CDN / Front Door")

AWS = NetworkHint("Amazon Web Services", "cloud", False)
GOOGLE_CLOUD = NetworkHint("Google Cloud", "cloud", False)
GOOGLE = NetworkHint("Google", "cloud", False)
AZURE = NetworkHint("Microsoft Azure", "cloud", False)
ORACLE = NetworkHint("Oracle Cloud", "cloud", False)
DIGITALOCEAN = NetworkHint("DigitalOcean", "hosting", False)
HETZNER = NetworkHint("Hetzner", "hosting", False)
OVH = NetworkHint("OVHcloud", "hosting", False)
LINODE = NetworkHint("Akamai Connected Cloud (Linode)", "hosting", False)
VULTR = NetworkHint("Vultr", "hosting", False)
SCALEWAY = NetworkHint("Scaleway", "hosting", False)
IONOS = NetworkHint("IONOS", "hosting", False)

ASN_HINTS: dict[int, NetworkHint] = {
    13335: CLOUDFLARE,
    209242: CLOUDFLARE,
    54113: FASTLY,
    16625: AKAMAI,
    20940: AKAMAI,
    12222: AKAMAI,
    21342: AKAMAI,
    21357: AKAMAI,
    33905: AKAMAI,
    34164: AKAMAI,
    35994: AKAMAI,
    36183: AKAMAI,
    43639: AKAMAI,
    15133: EDGIO,
    22822: EDGIO,
    19551: IMPERVA,
    30148: SUCURI,
    12989: STACKPATH,
    33438: STACKPATH,
    60068: CDN77,
    200325: BUNNY,
    199524: GCORE,
    36408: CDNETWORKS,
    16509: AWS,
    14618: AWS,
    396982: GOOGLE_CLOUD,
    15169: GOOGLE,
    8075: AZURE,
    31898: ORACLE,
    14061: DIGITALOCEAN,
    24940: HETZNER,
    16276: OVH,
    63949: LINODE,
    20473: VULTR,
    12876: SCALEWAY,
    8560: IONOS,
}

# Domain suffixes of names a CDN uses for the hosts it fronts; matched on label boundaries.
NAME_HINTS: tuple[tuple[str, NetworkHint], ...] = (
    ("cloudfront.net", CLOUDFRONT),
    ("cdn.cloudflare.net", CLOUDFLARE),
    ("cloudflare.net", CLOUDFLARE),
    ("akamaiedge.net", AKAMAI),
    ("akamai.net", AKAMAI),
    ("akamaitechnologies.com", AKAMAI),
    ("edgekey.net", AKAMAI),
    ("edgesuite.net", AKAMAI),
    ("fastly.net", FASTLY),
    ("fastlylb.net", FASTLY),
    ("global.ssl.fastly.net", FASTLY),
    ("azureedge.net", AZURE_CDN),
    ("azurefd.net", AZURE_CDN),
    ("edgecastcdn.net", EDGIO),
    ("llnwd.net", EDGIO),
    ("incapdns.net", IMPERVA),
    ("sucuri.net", SUCURI),
    ("stackpathdns.com", STACKPATH),
    ("cdn77.org", CDN77),
    ("b-cdn.net", BUNNY),
    ("gcdn.co", GCORE),
    ("cdngc.net", CDNETWORKS),
)


def _matches(name: str, suffix: str) -> bool:
    cleaned = name.strip().lower().rstrip(".")
    return cleaned == suffix or cleaned.endswith("." + suffix)


def hint_for(asn: int | None, names: Iterable[str] = ()) -> NetworkHint | None:
    """The best hint for an address: a CDN name in its CNAME chain or reverse DNS wins over its
    AS number (the AS of a CDN customer's origin tells nothing about the edge)."""
    for name in names:
        for suffix, hint in NAME_HINTS:
            if _matches(name, suffix):
                return hint
    return ASN_HINTS.get(asn) if asn is not None else None
