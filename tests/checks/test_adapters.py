"""Unit tests for the Web Risk adapter and its rule (PRV-01).

The GeoIP adapter that used to live here was replaced by the offline DB-IP provider
(`app/service/geo/`, tests in `tests/geo/`) and the Shodan adapter by the ports providers
(`app/service/ports/`, tests in `tests/ports/`). Web Risk follows in R4.
"""

from __future__ import annotations

import httpx

from app.service.checks.rules import evaluate_webrisk_findings
from app.service.checks.webrisk import lookup_threat_uri


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
