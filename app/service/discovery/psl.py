"""Public Suffix List screening, using the maintained list shipped by `publicsuffixlist`."""

from __future__ import annotations

from functools import lru_cache
from importlib.metadata import version

from publicsuffixlist import PublicSuffixList

# The package version carries the list date, e.g. 1.0.2.20261003. Reading it is a local
# metadata lookup; nothing here touches the network.
PSL_VERSION = version("publicsuffixlist")


@lru_cache(maxsize=1)
def _suffix_list() -> PublicSuffixList:
    return PublicSuffixList()


@lru_cache(maxsize=1)
def _icann_list() -> PublicSuffixList:
    return PublicSuffixList(only_icann=True)


def registrable_domain(domain_ascii: str) -> str | None:
    """The name a registry knows: the domain plus one label above its ICANN public suffix.

    ``shop.example.co.uk`` -> ``example.co.uk``; ``foo.blogspot.com`` -> ``blogspot.com`` (the
    private ``blogspot.com`` suffix is not a registry). ``None`` for a suffix or a single label.
    """
    domain = domain_ascii.strip(".").lower()
    result = _icann_list().privatesuffix(domain)
    return str(result) if result else None


def is_public_suffix(domain_ascii: str) -> bool:
    """True if the lower-case ASCII domain is a public suffix, a TLD or a single label.

    ICANN and private suffixes both count: ``co.kr``, ``github.io`` and ``blogspot.com`` are
    suffixes (many unrelated owners underneath), while ``foo.blogspot.com`` is not.
    """
    domain = domain_ascii.strip(".").lower()
    if "." not in domain:
        return True
    return bool(_suffix_list().publicsuffix(domain) == domain)
