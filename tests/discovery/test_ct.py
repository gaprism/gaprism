"""Tests for Certificate Transparency (CT) log discovery adapter and host extraction (COL-01)."""

import uuid

import httpx
import pytest
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.models.assessment import Assessment
from app.models.auth import User, Workspace
from app.models.discovery import CTNameObservation, Host, RunHost
from app.models.scan_run import ScanRun
from app.service.discovery.ct import (
    CTDiscoveryAdapter,
    CTEntry,
    CTPagedResult,
    commit_discovery_page,
)
from app.service.discovery.scope import canonicalise_domain


@pytest.fixture
def test_setup(db_session: Session) -> dict[str, uuid.UUID]:
    user = User(
        email="analyst@example.com",
        password="hashed_test_password",
        active=True,
    )
    workspace = Workspace(name="CT Workspace", enabled=True)
    db_session.add_all([user, workspace])
    db_session.flush()

    assessment = Assessment(
        workspace_id=workspace.id,
        supplier_label="Target Corp",
        scope_ascii="example.com",
        scope_display="example.com",
        created_by=user.id,
        owner_user_id=user.id,
    )
    db_session.add(assessment)
    db_session.flush()

    scan_run = ScanRun(
        workspace_id=workspace.id,
        assessment_id=assessment.id,
        requested_by=user.id,
        request_key=f"req-{uuid.uuid4()}",
        target_domain="example.com",
        status="running",
    )
    db_session.add(scan_run)
    db_session.flush()

    return {
        "workspace_id": workspace.id,
        "assessment_id": assessment.id,
        "run_id": scan_run.id,
    }


class TestCTAdapterParsing:
    def test_parse_items_format(self) -> None:
        data = {
            "items": [
                {"name": "api.example.com", "count": 2, "first_seen": "2026-01-01T00:00:00Z"},
                {"name": "*.example.com", "count": 5},
                {"name": "auth.example.com"},
            ],
            "next_cursor": "cur_123",
            "total_count": 3,
        }
        res = CTDiscoveryAdapter.parse_ct_response(data)
        assert len(res.entries) == 3
        assert res.next_cursor == "cur_123"
        assert res.has_more is True

        api_entry = res.entries[0]
        assert api_entry.name == "api.example.com"
        assert api_entry.entry_count == 2
        assert api_entry.is_wildcard is False

        wild_entry = res.entries[1]
        assert wild_entry.name == "*.example.com"
        assert wild_entry.is_wildcard is True

    def test_parse_certificates_format(self) -> None:
        data = {
            "certificates": [
                {"dns_names": ["mail.example.com", "*.mail.example.com"]},
                {"dns_names": ["vpn.example.com"]},
            ],
            "cursor": "cur_cert_99",
        }
        res = CTDiscoveryAdapter.parse_ct_response(data)
        assert len(res.entries) == 3
        assert res.next_cursor == "cur_cert_99"
        assert res.has_more is True
        assert any(e.name == "mail.example.com" and not e.is_wildcard for e in res.entries)
        assert any(e.name == "*.mail.example.com" and e.is_wildcard for e in res.entries)

    def test_fetch_page_with_mock_transport(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            if request.url.path == "/v1/hosts/example.com":
                return httpx.Response(
                    200,
                    json={
                        "hosts": [{"host": "app.example.com", "certs": 1}],
                        "has_next": True,
                        "next_cursor": "page2",
                    },
                )
            return httpx.Response(404)

        transport = httpx.MockTransport(handler)
        client = httpx.Client(transport=transport)
        adapter = CTDiscoveryAdapter(http_client=client)

        page = adapter.fetch_page("example.com")
        assert len(page.entries) == 1
        assert page.entries[0].name == "app.example.com"
        assert page.next_cursor == "page2"


class TestDiscoveryPageCommit:
    def test_col_01_cursor_pagination_deduplication_and_wildcards(
        self, db_session: Session, test_setup: dict[str, uuid.UUID]
    ) -> None:
        """COL-01: Verify CT log parser handles cursor pagination, duplicate hostnames,

        empty results, and wildcards without creating concrete hosts.
        """
        workspace_id = test_setup["workspace_id"]
        assessment_id = test_setup["assessment_id"]
        run_id = test_setup["run_id"]
        scope = canonicalise_domain("example.com")

        # Page 1 contains: concrete host, wildcard, and out-of-scope host
        page_1 = CTPagedResult(
            entries=[
                CTEntry(name="api.example.com", entry_count=1),
                CTEntry(name="*.example.com", entry_count=1, is_wildcard=True),
                CTEntry(name="otherdomain.com", entry_count=1),  # Out of scope
                CTEntry(name="api.example.com", entry_count=2),  # Duplicate within page
            ],
            next_cursor="cursor_page_2",
            has_more=True,
        )

        res_1 = commit_discovery_page(
            session=db_session,
            workspace_id=workspace_id,
            assessment_id=assessment_id,
            run_id=run_id,
            scope=scope,
            page_result=page_1,
        )
        db_session.flush()

        # Check Page 1 outcomes
        assert res_1.new_concrete_hosts_count == 1  # Only api.example.com
        assert res_1.wildcard_patterns_count == 1  # *.example.com
        assert res_1.next_cursor == "cursor_page_2"

        # Check DB: only 1 concrete host was created
        hosts = db_session.scalars(select(Host).where(Host.assessment_id == assessment_id)).all()
        assert len(hosts) == 1
        assert hosts[0].name_ascii == "api.example.com"

        # Check DB: wildcard is recorded as observation ONLY (INV-05)
        wild_obs = db_session.scalar(
            select(CTNameObservation).where(
                CTNameObservation.run_id == run_id,
                CTNameObservation.name_pattern == "*.example.com",
            )
        )
        assert wild_obs is not None
        assert wild_obs.is_wildcard is True

        # Ensure no concrete Host exists for wildcard pattern
        wild_host = db_session.scalar(
            select(Host).where(
                Host.assessment_id == assessment_id,
                Host.name_ascii.like("%*%"),
            )
        )
        assert wild_host is None

        # Page 2: empty page
        page_2 = CTPagedResult(entries=[], next_cursor=None, has_more=False)
        res_2 = commit_discovery_page(
            session=db_session,
            workspace_id=workspace_id,
            assessment_id=assessment_id,
            run_id=run_id,
            scope=scope,
            page_result=page_2,
        )
        db_session.flush()
        assert res_2.new_concrete_hosts_count == 0
        assert res_2.next_cursor is None

        # Verify ScanRun total_hosts_discovered
        run = db_session.scalar(select(ScanRun).where(ScanRun.id == run_id))
        assert run is not None
        assert run.total_hosts_discovered == 1

    def test_host_cap_enforcement(
        self, db_session: Session, test_setup: dict[str, uuid.UUID]
    ) -> None:
        workspace_id = test_setup["workspace_id"]
        assessment_id = test_setup["assessment_id"]
        run_id = test_setup["run_id"]
        scope = canonicalise_domain("example.com")

        # Page with 5 hosts, but max cap set to 2
        page = CTPagedResult(
            entries=[
                CTEntry(name="h1.example.com"),
                CTEntry(name="h2.example.com"),
                CTEntry(name="h3.example.com"),
                CTEntry(name="h4.example.com"),
            ],
            next_cursor=None,
            has_more=False,
        )

        res = commit_discovery_page(
            session=db_session,
            workspace_id=workspace_id,
            assessment_id=assessment_id,
            run_id=run_id,
            scope=scope,
            page_result=page,
            max_hosts_per_run=2,
        )
        db_session.flush()

        assert res.new_concrete_hosts_count == 2
        assert res.cap_reached is True

        eligible_count = db_session.scalar(
            select(func.count(RunHost.id)).where(
                RunHost.run_id == run_id,
                RunHost.eligibility == "eligible",
            )
        )
        excluded_count = db_session.scalar(
            select(func.count(RunHost.id)).where(
                RunHost.run_id == run_id,
                RunHost.eligibility == "excluded",
                RunHost.exclusion_reason == "run_host_cap_exceeded",
            )
        )
        assert eligible_count == 2
        assert excluded_count == 2
