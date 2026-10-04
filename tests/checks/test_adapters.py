"""Unit tests for GeoIP, Shodan, and WebRisk adapters and rule evaluation (PRV-01, FIND-01)."""

from __future__ import annotations

from collections.abc import Callable

import httpx

from app.service.checks.geoip import lookup_geoip
from app.service.checks.rules import (
    evaluate_geoip_findings,
    evaluate_shodan_findings,
    evaluate_webrisk_findings,
)
from app.service.checks.shodan import lookup_shodan_host
from app.service.checks.webrisk import lookup_threat_uri


def _geoip_client(handler: Callable[[httpx.Request], httpx.Response]) -> httpx.Client:
    """An HTTP client that answers from ``handler``; unit tests never reach the network."""
    return httpx.Client(transport=httpx.MockTransport(handler))


class TestGeoIPAdapter:
    def test_missing_dataset_never_fabricates_a_location(self) -> None:
        """No dataset and no API fallback means "unlicensed", not a guessed location."""
        for address in ("193.134.1.1", "194.12.1.1", "8.8.8.8"):
            res = lookup_geoip(address, allow_fallback=False)
            assert res.status == "unlicensed"
            assert res.verdict == "unknown"
            assert res.iso_country_code is None
            assert res.asn is None
            findings = evaluate_geoip_findings(res)
            assert len(findings) == 1
            assert findings[0].rule_id == "COLLECTION_INCOMPLETE"

    def test_api_fallback_maps_the_provider_response(self) -> None:
        """The keyless API fallback (enabled by default) is mocked: no network in unit tests."""
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url))
            return httpx.Response(
                200,
                json={
                    "success": True,
                    "country_code": "CH",
                    "country": "Switzerland",
                    "city": "Zurich",
                    "is_eu": False,
                    "connection": {"asn": 3303, "org": "Swisscom"},
                },
            )

        res = lookup_geoip("193.134.1.1", http_client=_geoip_client(handler))
        assert seen == ["https://ipwho.is/193.134.1.1"]
        assert (res.status, res.verdict) == ("succeeded", "match")
        assert (res.iso_country_code, res.city_name, res.asn, res.as_org) == (
            "CH",
            "Zurich",
            3303,
            "Swisscom",
        )

    def test_api_fallback_failures_are_typed_not_empty(self) -> None:
        """Rate limits, provider failures and junk responses never look like "no location"."""
        cases = {
            "provider_rate_limited": httpx.Response(429),
            "provider_http_503": httpx.Response(503),
            "invalid_provider_response": httpx.Response(200, text="<html>not json</html>"),
            "provider_lookup_failed": httpx.Response(200, json={"success": False}),
        }
        for reason, response in cases.items():
            res = lookup_geoip("8.8.8.8", http_client=_geoip_client(lambda _, r=response: r))
            assert (res.status, res.reason_code, res.verdict) == ("failed", reason, "unknown")

    def test_api_fallback_network_errors_are_typed(self) -> None:
        def timeout(request: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("slow", request=request)

        def refused(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("refused", request=request)

        assert lookup_geoip("8.8.8.8", http_client=_geoip_client(timeout)).reason_code == (
            "provider_timeout"
        )
        assert lookup_geoip("8.8.8.8", http_client=_geoip_client(refused)).reason_code == (
            "provider_unavailable"
        )

    def test_private_ip_rejected(self) -> None:
        res = lookup_geoip("192.168.1.1")
        assert res.status == "failed"
        assert res.reason_code == "private_ip"

        res_loopback = lookup_geoip("127.0.0.1")
        assert res_loopback.status == "failed"
        assert res_loopback.reason_code == "private_ip"

    def test_invalid_ip_format(self) -> None:
        res = lookup_geoip("not-an-ip")
        assert res.status == "failed"
        assert res.reason_code == "invalid_ip"

    def test_unlicensed_missing_dataset(self) -> None:
        res = lookup_geoip(
            "93.184.216.34", db_path="/nonexistent/GeoLite2.mmdb", allow_fallback=False
        )
        assert res.status == "unlicensed"
        assert res.reason_code == "dataset_not_installed"


class TestShodanAdapter:
    def test_prv_01_missing_api_key(self) -> None:
        res = lookup_shodan_host("93.184.216.34", api_key=None)
        assert res.status == "unlicensed"
        assert res.reason_code == "missing_api_key"
        assert res.verdict == "unknown"

        findings = evaluate_shodan_findings(res)
        assert len(findings) == 1
        assert findings[0].rule_id == "COLLECTION_INCOMPLETE"

    def test_prv_01_404_no_information_is_clean_no_match(self) -> None:
        transport = httpx.MockTransport(
            lambda req: httpx.Response(404, json={"error": "No information available"})
        )
        client = httpx.Client(transport=transport)
        try:
            res = lookup_shodan_host("93.184.216.34", api_key="test-key", http_client=client)
            assert res.status == "succeeded"
            assert res.verdict == "no_match"
            assert len(res.services) == 0
            assert len(res.vulnerabilities) == 0

            findings = evaluate_shodan_findings(res)
            assert len(findings) == 0
        finally:
            client.close()

    def test_prv_01_auth_failure(self) -> None:
        transport = httpx.MockTransport(
            lambda req: httpx.Response(401, json={"error": "Invalid API key"})
        )
        client = httpx.Client(transport=transport)
        try:
            res = lookup_shodan_host("93.184.216.34", api_key="bad-key", http_client=client)
            assert res.status == "failed"
            assert res.reason_code == "auth_failed"
            assert res.verdict == "unknown"
        finally:
            client.close()

    def test_prv_01_quota_exhausted(self) -> None:
        transport = httpx.MockTransport(
            lambda req: httpx.Response(429, json={"error": "Rate limit exceeded"})
        )
        client = httpx.Client(transport=transport)
        try:
            res = lookup_shodan_host("93.184.216.34", api_key="test-key", http_client=client)
            assert res.status == "failed"
            assert res.reason_code == "quota_exhausted"
        finally:
            client.close()

    def test_prv_01_timeout(self) -> None:
        def timeout_handler(req: httpx.Request) -> httpx.Response:
            raise httpx.ReadTimeout("Socket timeout")

        client = httpx.Client(transport=httpx.MockTransport(timeout_handler))
        try:
            res = lookup_shodan_host("93.184.216.34", api_key="test-key", http_client=client)
            assert res.status == "failed"
            assert res.reason_code == "timeout"
        finally:
            client.close()

    def test_find_01_shared_infrastructure_attribution(self) -> None:
        # Mock Shodan response for Cloudflare CDN IP with a reported CVE
        payload = {
            "ip_str": "104.16.123.96",
            "org": "Cloudflare, Inc.",
            "isp": "Cloudflare, Inc.",
            "tags": ["cdn", "cloud"],
            "hostnames": [
                "cloudflare.com",
                "other1.com",
                "other2.com",
                "other3.com",
                "other4.com",
                "other5.com",
            ],
            "data": [
                {"port": 443, "transport": "tcp", "product": "Cloudflare server", "version": "1.0"}
            ],
            "vulns": {
                "CVE-2023-9999": {
                    "cvss": 9.8,
                    "summary": "Critical vulnerability on edge server",
                    "verified": True,
                }
            },
        }
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
        client = httpx.Client(transport=transport)
        try:
            res = lookup_shodan_host(
                "104.16.123.96",
                api_key="test-key",
                target_hostname="target-saas.com",
                http_client=client,
            )
            assert res.status == "succeeded"
            assert res.is_shared_infrastructure is True
            assert len(res.vulnerabilities) == 1
            vuln = res.vulnerabilities[0]
            assert vuln.attribution == "shared_infrastructure"

            # Rule evaluation: finding attributed to shared_infrastructure with warning (FIND-01)
            findings = evaluate_shodan_findings(res, target_hostname="target-saas.com")
            cve_finding = next(f for f in findings if f.rule_id == "SHODAN_CVE_OBSERVED")
            assert cve_finding.attribution == "shared_infrastructure"
            assert cve_finding.severity == "informational"
        finally:
            client.close()

    def test_find_01_hostname_supported_attribution(self) -> None:
        # Dedicated host where target hostname is verified in Shodan hostnames
        payload = {
            "ip_str": "193.134.1.5",
            "org": "Dedicated Hosting Corp",
            "isp": "Dedicated ISP",
            "tags": [],
            "hostnames": ["api.target-saas.com"],
            "data": [{"port": 443, "transport": "tcp", "product": "nginx", "version": "1.24"}],
            "vulns": {
                "CVE-2023-1111": {
                    "cvss": 7.5,
                    "summary": "High severity web server vulnerability",
                    "verified": True,
                }
            },
        }
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
        client = httpx.Client(transport=transport)
        try:
            res = lookup_shodan_host(
                "193.134.1.5",
                api_key="test-key",
                target_hostname="api.target-saas.com",
                http_client=client,
            )
            assert res.status == "succeeded"
            assert res.is_shared_infrastructure is False
            vuln = res.vulnerabilities[0]
            assert vuln.attribution == "hostname_supported"

            findings = evaluate_shodan_findings(res, target_hostname="api.target-saas.com")
            cve_finding = next(f for f in findings if f.rule_id == "SHODAN_CVE_OBSERVED")
            assert cve_finding.attribution == "hostname_supported"
            assert cve_finding.severity == "high"
        finally:
            client.close()


class TestWebRiskAdapter:
    def test_prv_01_missing_api_key(self) -> None:
        res = lookup_threat_uri("https://example.com", api_key=None)
        assert res.status == "unlicensed"
        assert res.reason_code == "missing_api_key"

    def test_prv_01_clean_url_no_match(self) -> None:
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json={}))
        client = httpx.Client(transport=transport)
        try:
            res = lookup_threat_uri("https://example.com", api_key="valid-key", http_client=client)
            assert res.status == "succeeded"
            assert res.verdict == "no_match"
            assert len(res.threats) == 0

            findings = evaluate_webrisk_findings(res)
            assert len(findings) == 0
        finally:
            client.close()

    def test_prv_01_threat_detected_match(self) -> None:
        payload = {
            "threat": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING"],
                "expireTime": "2026-10-02T12:00:00Z",
            }
        }
        transport = httpx.MockTransport(lambda req: httpx.Response(200, json=payload))
        client = httpx.Client(transport=transport)
        try:
            res = lookup_threat_uri(
                "https://malicious-saas.com", api_key="valid-key", http_client=client
            )
            assert res.status == "succeeded"
            assert res.verdict == "match"
            assert len(res.threats) == 2

            findings = evaluate_webrisk_findings(res)
            assert len(findings) == 1
            finding = findings[0]
            assert finding.rule_id == "REPUTATION_MATCH"
            assert finding.severity == "high"
            assert "MALWARE" in finding.message_parameters["threat_types"]
        finally:
            client.close()

    def test_prv_01_auth_failure(self) -> None:
        err_body = {"error": {"code": 403, "message": "API key invalid"}}
        transport = httpx.MockTransport(lambda req: httpx.Response(403, json=err_body))
        client = httpx.Client(transport=transport)
        try:
            res = lookup_threat_uri("https://example.com", api_key="bad-key", http_client=client)
            assert res.status == "failed"
            assert res.reason_code == "auth_failed"
        finally:
            client.close()
