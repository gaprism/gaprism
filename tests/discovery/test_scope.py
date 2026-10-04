"""Unit tests for domain scope normalisation, IDNA conversion, PSL screening, and boundaries."""

import pytest

from app.service.discovery.scope import (
    DomainScope,
    ScopeValidationError,
    canonicalise_domain,
    is_in_scope,
)


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

    def test_reject_empty_or_invalid_types(self) -> None:
        with pytest.raises(ScopeValidationError, match="cannot be empty"):
            canonicalise_domain("")
        with pytest.raises(ScopeValidationError, match="cannot be empty"):
            canonicalise_domain("   ")

    def test_reject_url_syntax(self) -> None:
        with pytest.raises(ScopeValidationError, match="URL schemes"):
            canonicalise_domain("https://example.com")
        with pytest.raises(ScopeValidationError, match="URL schemes"):
            canonicalise_domain("http://example.com/login")
        with pytest.raises(ScopeValidationError, match="Path syntax"):
            canonicalise_domain("example.com/api")
        with pytest.raises(ScopeValidationError, match="Userinfo"):
            canonicalise_domain("admin@example.com")
        with pytest.raises(ScopeValidationError, match="Port numbers"):
            canonicalise_domain("example.com:443")
        with pytest.raises(ScopeValidationError, match="Query strings"):
            canonicalise_domain("example.com?query=1")
        with pytest.raises(ScopeValidationError, match="Query strings"):
            canonicalise_domain("example.com#section")

    def test_reject_wildcards(self) -> None:
        with pytest.raises(ScopeValidationError, match="Wildcard"):
            canonicalise_domain("*.example.com")
        with pytest.raises(ScopeValidationError, match="Wildcard"):
            canonicalise_domain("*")

    def test_reject_ip_literals(self) -> None:
        with pytest.raises(ScopeValidationError, match="IP address literals"):
            canonicalise_domain("127.0.0.1")
        with pytest.raises(ScopeValidationError, match="IP address literals"):
            canonicalise_domain("192.168.1.1")
        with pytest.raises(ScopeValidationError, match="IP address literals"):
            canonicalise_domain("::1")
        with pytest.raises(ScopeValidationError, match="IP address literals"):
            canonicalise_domain("2001:db8::1")

    def test_reject_label_syntax_violations(self) -> None:
        # Empty label
        with pytest.raises(ScopeValidationError, match="empty labels"):
            canonicalise_domain("example..com")
        # Leading hyphen
        with pytest.raises(ScopeValidationError, match="invalid characters"):
            canonicalise_domain("-example.com")
        # Trailing hyphen
        with pytest.raises(ScopeValidationError, match="invalid characters"):
            canonicalise_domain("example-.com")
        # Underscore in domain label
        with pytest.raises(ScopeValidationError, match="invalid characters"):
            canonicalise_domain("bad_label.com")
        # Label exceeding 63 chars
        long_label = "a" * 64
        with pytest.raises(ScopeValidationError, match="exceeds maximum length of 63"):
            canonicalise_domain(f"{long_label}.com")

    def test_reject_public_suffixes(self) -> None:
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("com")
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("ch")
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("de")
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("co.uk")
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("github.io")
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain("s3.amazonaws.com")

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
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
            canonicalise_domain(suffix)

    def test_names_below_a_suffix_are_valid_scopes(self) -> None:
        assert canonicalise_domain("vendor.blogspot.com").canonical == "vendor.blogspot.com"
        assert canonicalise_domain("vendor.co.uk").canonical == "vendor.co.uk"
        # Exception rule (!city.kobe.jp): this is a registrable name, not a suffix.
        assert canonicalise_domain("city.kobe.jp").canonical == "city.kobe.jp"
        # Wildcard rule (*.ck) makes any single label under .ck a suffix.
        with pytest.raises(ScopeValidationError, match="public suffix / TLD"):
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
