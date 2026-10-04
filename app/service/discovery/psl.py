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


def is_public_suffix(domain_ascii: str) -> bool:
    """True if the lower-case ASCII domain is a public suffix, a TLD or a single label.

    ICANN and private suffixes both count: ``co.kr``, ``github.io`` and ``blogspot.com`` are
    suffixes (many unrelated owners underneath), while ``foo.blogspot.com`` is not.
    """
    domain = domain_ascii.strip(".").lower()
    if "." not in domain:
        return True
    return bool(_suffix_list().publicsuffix(domain) == domain)
