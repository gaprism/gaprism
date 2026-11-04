"""Unit tests for domain scope normalisation, IDNA conversion, PSL screening, and boundaries."""

import pytest

from app.service.discovery.scope import (
    DomainScope,
    ScopeValidationError,
    canonicalise_domain,
    is_in_scope,
)

EMPTY = "Enter the vendor's domain, for example example.com."
IP_ADDRESS = (
    "That is an IP address, not a domain name. "
    "Enter the vendor's domain name instead, for example example.com."
)
SCHEME = 'Enter the domain only, without "https://" or another scheme.'
PATH = "Enter the domain only, without a path. Remove the slash and everything after it."
USER = 'Enter the domain only. Remove the "@" and everything before it.'
PORT = "Enter the domain only, without a port number. Remove the colon and what follows it."
QUERY = 'Enter the domain only. Remove the "?" or "#" and everything after it.'
WILDCARD = (
    "Enter a single domain, such as example.com. "
    'A wildcard such as "*.example.com" is not accepted.'
)
EMPTY_PART = (
    "The domain has an empty part: two dots in a row, or a dot at the start. Check the spelling."
)


def long_part(start: str) -> str:
    return (
        f'A part of the domain ("{start}...") has more than 63 characters, '
        "which a domain name cannot have. Check the spelling."
    )


def bad_part(part: str) -> str:
    return (
        f'"{part}" cannot be part of a domain name. '
        "Use letters, digits and hyphens, with no hyphen at the start or end of a part."
    )


def suffix(domain: str) -> str:
    return (
        f'"{domain}" is a top-level domain or public suffix, '
        "not one organisation's domain. Enter the vendor's own domain, "
        f"for example vendor.{domain}."
    )


def too_long(length: int) -> str:
    return (
        f"The domain has {length} characters. A domain name has at most 253. "
        "Check what you entered."
    )


# What a person who typed one of these is told: what happened, and what to do about it.
REFUSALS = [
    ("", EMPTY),
    ("   ", EMPTY),
    ("127.0.0.1", IP_ADDRESS),
    ("192.168.1.1", IP_ADDRESS),
    ("::1", IP_ADDRESS),
    ("2001:db8::1", IP_ADDRESS),
    ("https://example.com", SCHEME),
    ("http://example.com/login", SCHEME),
    ("https:example.com", SCHEME),
    ("example.com/api", PATH),
    ("admin@example.com", USER),
    ("example.com:443", PORT),
    ("[2001:db8::1]:443", PORT),
    ("example.com?query=1", QUERY),
    ("example.com#section", QUERY),
    ("*.example.com", WILDCARD),
    ("*", WILDCARD),
    ("example..com", EMPTY_PART),
    (".example.com", EMPTY_PART),
    ("-example.com", bad_part("-example")),
    ("example-.com", bad_part("example-")),
    ("bad_label.com", bad_part("bad_label")),
    ("vendor example.com", bad_part("vendor example")),
    ("a" * 64 + ".com", long_part("a" * 10)),
    ("com", suffix("com")),
    ("co.uk", suffix("co.uk")),
    ("localhost", suffix("localhost")),
    ("s3.amazonaws.com", suffix("s3.amazonaws.com")),
    (("a" * 60 + ".") * 5 + "com", too_long(308)),
]


class TestScopeCanonicalisation:
    def test_valid_standard_domains(self) -> None:
        scope = canonicalise_domain("example.com")
        assert scope.canonical == "example.com"
        assert scope.unicode == "example.com"
        assert scope.raw_input == "example.com"

        sub_scope = canonicalise_domain("api.sub.example.com")
        assert sub_scope.canonical == "api.sub.example.com"

    def test_whitespace_and_trailing_dot(self) -> None:
        scope = canonicalise_domain("  example.com.  ")
        assert scope.canonical == "example.com"
        assert scope.unicode == "example.com"

    def test_case_insensitive_normalisation(self) -> None:
        scope = canonicalise_domain("ExAmPlE.CoM")
        assert scope.canonical == "example.com"

    def test_idna_internationalised_domains(self) -> None:
        # German umlaut domain (münchen.de -> xn--mnchen-3ya.de)
        scope = canonicalise_domain("münchen.de")
        assert scope.canonical == "xn--mnchen-3ya.de"
        assert scope.unicode == "münchen.de"

        # Swiss domain (zürich.ch -> xn--zrich-kva.ch)
        scope_ch = canonicalise_domain("zürich.ch")
        assert scope_ch.canonical == "xn--zrich-kva.ch"
        assert scope_ch.unicode == "zürich.ch"

    @pytest.mark.parametrize(("entered", "message"), REFUSALS)
    def test_every_refusal_says_what_happened_and_what_to_do(
        self, entered: str, message: str
    ) -> None:
        with pytest.raises(ScopeValidationError) as raised:
            canonicalise_domain(entered)
        assert str(raised.value) == message

    @pytest.mark.parametrize(("entered", "message"), REFUSALS)
    def test_a_refusal_keeps_its_text_apart_from_what_fills_it(
        self, entered: str, message: str
    ) -> None:
        """The view translates the text first and fills the placeholders after."""
        with pytest.raises(ScopeValidationError) as raised:
            canonicalise_domain(entered)
        error = raised.value
        assert error.message % error.params == str(error)
        for name in error.params:
            assert f"%({name})" in error.message, name

    def test_a_refusal_carries_the_part_that_is_wrong(self) -> None:
        with pytest.raises(ScopeValidationError) as raised:
            canonicalise_domain("co.uk")
        assert raised.value.params == {"domain": "co.uk"}
        with pytest.raises(ScopeValidationError) as raised:
            canonicalise_domain("bad_label.com")
        assert raised.value.params == {"part": "bad_label"}

    @pytest.mark.parametrize(
        "suffix",
        [
            "co.kr",
            "com.mx",
            "co.in",
            "ne.kr",
            "blogspot.com",
            "myshopify.com",
            "azureedge.net",
            "web.core.windows.net",
        ],
    )
    def test_reject_suffixes_the_old_curated_list_missed(self, suffix: str) -> None:
        """A scan of a suffix would enumerate every unrelated owner underneath it."""
        with pytest.raises(ScopeValidationError, match="public suffix"):
            canonicalise_domain(suffix)

    def test_names_below_a_suffix_are_valid_scopes(self) -> None:
        assert canonicalise_domain("vendor.blogspot.com").canonical == "vendor.blogspot.com"
        assert canonicalise_domain("vendor.co.uk").canonical == "vendor.co.uk"
        # Exception rule (!city.kobe.jp): this is a registrable name, not a suffix.
        assert canonicalise_domain("city.kobe.jp").canonical == "city.kobe.jp"
        # Wildcard rule (*.ck) makes any single label under .ck a suffix.
        with pytest.raises(ScopeValidationError, match="public suffix"):
            canonicalise_domain("anything.ck")

    def test_the_list_version_is_recorded_with_the_scope(self) -> None:
        scope = canonicalise_domain("example.com")
        assert scope.psl_version and scope.psl_version[0].isdigit()


class TestScopeMembership:
    @pytest.fixture
    def scope(self) -> DomainScope:
        return canonicalise_domain("example.com")

    def test_exact_domain_match(self, scope: DomainScope) -> None:
        assert is_in_scope("example.com", scope) is True
        assert is_in_scope("example.com.", scope) is True
        assert is_in_scope("EXAMPLE.COM", scope) is True

    def test_subdomain_in_scope(self, scope: DomainScope) -> None:
        assert is_in_scope("api.example.com", scope) is True
        assert is_in_scope("deep.sub.api.example.com", scope) is True

    def test_out_of_scope_boundary_rejection(self, scope: DomainScope) -> None:
        # Substring / sibling domain
        assert is_in_scope("notexample.com", scope) is False
        assert is_in_scope("myexample.com", scope) is False
        assert is_in_scope("example.ch", scope) is False

        # Attacker subdomain spoofing
        assert is_in_scope("example.com.evil.com", scope) is False
        assert is_in_scope("example.com.attacker.test", scope) is False

    def test_idna_scope_matching(self) -> None:
        scope_idna = canonicalise_domain("münchen.de")
        assert is_in_scope("münchen.de", scope_idna) is True
        assert is_in_scope("xn--mnchen-3ya.de", scope_idna) is True
        assert is_in_scope("sub.münchen.de", scope_idna) is True
        assert is_in_scope("sub.xn--mnchen-3ya.de", scope_idna) is True
        assert is_in_scope("other-münchen.de", scope_idna) is False
