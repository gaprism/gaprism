"""Adversarial and functional test suite for the Anti-SSRF egress gate (NET-01, NET-02)."""

import ipaddress

import httpx
import pytest

from runner.dns import (
    DNSResolutionError,
    SSRFBlockedError,
    ip_block_reason,
    is_ip_public,
    resolve_and_screen,
)
from runner.egress import EgressHTTPClient, SSRFRedirectBlockedError


class TestIPPublicScreening:
    def test_public_ipv4_allowed(self) -> None:
        assert is_ip_public("93.184.216.34") is True
        assert is_ip_public("8.8.8.8") is True
        assert is_ip_public("1.1.1.1") is True
        assert is_ip_public("151.101.1.140") is True

    def test_private_rfc1918_ipv4_blocked(self) -> None:
        assert is_ip_public("10.0.0.1") is False
        assert is_ip_public("10.254.254.254") is False
        assert is_ip_public("172.16.0.1") is False
        assert is_ip_public("172.31.255.255") is False
        assert is_ip_public("192.168.0.1") is False
        assert is_ip_public("192.168.1.100") is False

    def test_loopback_and_special_ipv4_blocked(self) -> None:
        assert is_ip_public("127.0.0.1") is False
        assert is_ip_public("127.1.2.3") is False
        assert is_ip_public("0.0.0.0") is False
        assert is_ip_public("255.255.255.255") is False

    def test_cloud_metadata_and_link_local_blocked(self) -> None:
        # AWS / GCP / Azure metadata endpoint
        assert is_ip_public("169.254.169.254") is False
        assert is_ip_public("169.254.1.1") is False

    def test_public_ipv6_allowed(self) -> None:
        assert is_ip_public("2606:2800:220:1:248:1893:25c8:1946") is True
        assert is_ip_public("2001:4860:4860::8888") is True

    def test_private_and_special_ipv6_blocked(self) -> None:
        assert is_ip_public("::1") is False
        assert is_ip_public("::") is False
        assert is_ip_public("fe80::1") is False  # Link local
        assert is_ip_public("fc00::1") is False  # ULA
        assert is_ip_public("fd12:3456:789a:1::1") is False  # ULA

    def test_ipv4_mapped_ipv6_blocked(self) -> None:
        # IPv4-mapped loopback & metadata
        assert is_ip_public("::ffff:127.0.0.1") is False
        assert is_ip_public("::ffff:169.254.169.254") is False
        assert is_ip_public("::ffff:10.0.0.1") is False
        assert is_ip_public("::ffff:192.168.1.1") is False
        # IPv4-mapped public IP
        assert is_ip_public("::ffff:93.184.216.34") is True


class TestBlockReason:
    """``ip_block_reason`` labels what ``is_ip_public`` refuses; it never disagrees with it."""

    @pytest.mark.parametrize(
        ("ip", "reason"),
        [
            ("10.1.2.3", "private"),
            ("192.168.0.9", "private"),
            ("127.0.0.1", "loopback"),
            ("::1", "loopback"),
            ("169.254.169.254", "link_local"),
            ("fe80::1", "link_local"),
            ("224.0.0.1", "multicast"),
            ("0.0.0.0", "unspecified"),
            ("fd12:3456:789a:1::1", "private"),
            ("::ffff:10.0.0.1", "private"),  # IPv4-mapped: judged by the address inside
            ("::ffff:127.0.0.1", "loopback"),
            ("240.0.0.1", "reserved"),
            ("100.64.0.1", "special_use"),  # carrier-grade NAT
            ("not-an-ip", "invalid"),
        ],
    )
    def test_names_the_category(self, ip: str, reason: str) -> None:
        assert ip_block_reason(ip) == reason

    @pytest.mark.parametrize(
        "ip", ["93.184.216.34", "1.1.1.1", "2606:2800:220:1:248:1893:25c8:1946"]
    )
    def test_public_addresses_have_no_reason(self, ip: str) -> None:
        assert ip_block_reason(ip) is None

    @pytest.mark.parametrize(
        "ip",
        [
            "10.0.0.1",
            "127.0.0.1",
            "169.254.1.1",
            "100.64.1.1",
            "198.51.100.7",
            "::1",
            "fc00::1",
            "bad",
        ],
    )
    def test_agrees_with_the_gate(self, ip: str) -> None:
        assert (ip_block_reason(ip) is None) == is_ip_public(ip)


class TestDNSResolverAndAntiSSRF:
    def test_net01_reject_localhost_and_private_literals(self) -> None:
        with pytest.raises(SSRFBlockedError, match="loopback/local"):
            resolve_and_screen("localhost")

        with pytest.raises(SSRFBlockedError, match="private/forbidden"):
            resolve_and_screen("127.0.0.1")

        with pytest.raises(SSRFBlockedError, match="private/forbidden"):
            resolve_and_screen("169.254.169.254")

        with pytest.raises(SSRFBlockedError, match="private/forbidden"):
            resolve_and_screen("10.0.0.5")

    def test_net01_resolve_safe_domain(self) -> None:
        def mock_resolver(_host: str) -> list[str]:
            return ["93.184.216.34", "2606:2800:220:1:248:1893:25c8:1946"]

        ips = resolve_and_screen("example.com", resolver_fn=mock_resolver)
        assert len(ips) == 2
        assert ipaddress.IPv4Address("93.184.216.34") in ips

    def test_net01_mixed_answer_set_rejection(self) -> None:
        """NET-01: Reject mixed answer set if ANY address is private/forbidden."""

        def mock_resolver(_host: str) -> list[str]:
            return ["93.184.216.34", "127.0.0.1"]

        with pytest.raises(SSRFBlockedError, match="returned forbidden destination IP"):
            resolve_and_screen("mixed.example.com", resolver_fn=mock_resolver)

    def test_empty_or_failed_dns_resolution(self) -> None:
        def mock_resolver(_host: str) -> list[str]:
            return []

        with pytest.raises(DNSResolutionError, match="no A or AAAA records"):
            resolve_and_screen("unresolved.example.com", resolver_fn=mock_resolver)


class TestEgressHTTPClient:
    def test_net01_blocked_direct_private_requests(self) -> None:
        client = EgressHTTPClient()
        with pytest.raises(SSRFBlockedError):
            client.get("http://127.0.0.1:8080/admin")

        with pytest.raises(SSRFBlockedError):
            client.get("http://169.254.169.254/latest/meta-data/")

        with pytest.raises(SSRFBlockedError):
            client.get("http://localhost:3000/")

    def test_net01_blocked_redirect_to_private_ip(self) -> None:
        """NET-01 / NET-02: Public endpoint redirecting to metadata/localhost is blocked."""
        dns_map = {
            "public.example.com": ["93.184.216.34"],
            "attacker.local": ["127.0.0.1"],
            "metadata.internal": ["169.254.169.254"],
        }

        def mock_resolver(host: str) -> list[str]:
            return dns_map.get(host, ["93.184.216.34"])

        # Transport simulating a 302 redirect from public -> metadata
        def redirect_handler(request: httpx.Request) -> httpx.Response:
            if request.headers["Host"] == "public.example.com":
                return httpx.Response(
                    302,
                    headers={"Location": "http://169.254.169.254/latest/meta-data/"},
                )
            return httpx.Response(200, text="Internal Secret")

        transport = httpx.MockTransport(redirect_handler)
        client = EgressHTTPClient(
            resolver_fn=mock_resolver,
            custom_transport=transport,
        )

        with pytest.raises(SSRFRedirectBlockedError, match="Blocked redirect"):
            client.get("https://public.example.com/login")

    def test_net01_successful_safe_request_and_safe_redirect(self) -> None:
        dns_map = {
            "origin.example.com": ["93.184.216.34"],
            "target.example.com": ["93.184.216.35"],
        }

        def mock_resolver(host: str) -> list[str]:
            return dns_map.get(host, ["93.184.216.34"])

        def redirect_handler(request: httpx.Request) -> httpx.Response:
            if request.headers["Host"] == "origin.example.com":
                return httpx.Response(
                    301,
                    headers={"Location": "https://target.example.com/home"},
                )
            return httpx.Response(200, text="<html>Safe Landing</html>")

        transport = httpx.MockTransport(redirect_handler)
        client = EgressHTTPClient(
            resolver_fn=mock_resolver,
            custom_transport=transport,
        )

        response = client.get("https://origin.example.com/")
        assert response.status_code == 200
        assert "Safe Landing" in response.text
        assert response.url == "https://target.example.com/home"
        assert len(response.redirect_history) == 1
        assert response.redirect_history[0] == ("https://origin.example.com/", "93.184.216.34")

    def test_reject_non_http_schemes(self) -> None:
        client = EgressHTTPClient()
        with pytest.raises(SSRFBlockedError, match="forbidden"):
            client.get("file:///etc/passwd")

        with pytest.raises(SSRFBlockedError, match="forbidden"):
            client.get("gopher://127.0.0.1:70")
