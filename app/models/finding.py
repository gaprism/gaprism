"""Findings produced by rules, and the team's decisions about them."""

from __future__ import annotations

import uuid
from datetime import date, datetime
from typing import Any

from sqlalchemy import (
    CheckConstraint,
    Date,
    DateTime,
    ForeignKey,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column

from app.models.base import (
    JSONB_EMPTY_ARRAY,
    JSONB_EMPTY_OBJECT,
    BaseUUIDModel,
    TimestampMixin,
    sql_in,
    utc_now,
)

SEVERITIES = ("informational", "low", "medium", "high", "critical")
CONFIDENCES = ("unknown", "low", "medium", "high")
# hostname_supported: evidence names the host · ip_only: observed on its IP only ·
# shared_infrastructure: IP is shared (CDN/hosting) · domain: applies to the whole domain.
ATTRIBUTIONS = ("hostname_supported", "ip_only", "shared_infrastructure", "domain")
DISPOSITION_STATUSES = ("accepted", "false_positive")


class Finding(BaseUUIDModel, TimestampMixin):
    """A rule result for one scan. Evidence stays in ``check_result``; this is the judgement."""

    __tablename__ = "finding"

    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scan.id", ondelete="CASCADE"),
        nullable=False,
    )
    host_id: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("host.id", ondelete="CASCADE"),
        nullable=True,
        index=True,
    )
    rule_id: Mapped[str] = mapped_column(String(64), nullable=False)
    rule_version: Mapped[str] = mapped_column(String(16), nullable=False, default="1")
    subject: Mapped[str] = mapped_column(String(255), nullable=False)
    severity: Mapped[str] = mapped_column(String(16), nullable=False)
    confidence: Mapped[str] = mapped_column(String(16), nullable=False)
    attribution: Mapped[str] = mapped_column(String(32), nullable=False)
    params: Mapped[dict[str, Any]] = mapped_column(
        JSONB, nullable=False, default=dict, server_default=JSONB_EMPTY_OBJECT
    )
    evidence: Mapped[list[str]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=JSONB_EMPTY_ARRAY
    )
    # sha256(rule_id | subject): stable across scans, so decisions carry over to re-scans.
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)

    __table_args__ = (
        UniqueConstraint("scan_id", "fingerprint", name="uq_finding_scan_fingerprint"),
        CheckConstraint(sql_in("severity", SEVERITIES), name="ck_finding_severity"),
        CheckConstraint(sql_in("confidence", CONFIDENCES), name="ck_finding_confidence"),
        CheckConstraint(sql_in("attribution", ATTRIBUTIONS), name="ck_finding_attribution"),
    )

    def __repr__(self) -> str:
        return f"<Finding {self.rule_id} {self.severity} ({self.id})>"


class FindingDisposition(BaseUUIDModel, TimestampMixin):
    """A team decision about a finding (accepted / false positive), kept per assessment.

    Keyed by the finding fingerprint rather than a finding row, so it survives re-scans.
    The evidence is never changed. Reopening a finding deletes the row; every change is
    appended to ``history`` first.
    """

    __tablename__ = "finding_disposition"

    assessment_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("assessment.id", ondelete="CASCADE"),
        nullable=False,
    )
    fingerprint: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(16), nullable=False)
    reason: Mapped[str] = mapped_column(Text, nullable=False)
    decided_by: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("user.id", ondelete="RESTRICT"),
        nullable=False,
    )
    decided_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), nullable=False, default=utc_now
    )
    review_by: Mapped[date | None] = mapped_column(Date, nullable=True)
    history: Mapped[list[dict[str, Any]]] = mapped_column(
        JSONB, nullable=False, default=list, server_default=JSONB_EMPTY_ARRAY
    )

    __table_args__ = (
        UniqueConstraint("assessment_id", "fingerprint", name="uq_finding_disposition_fingerprint"),
        CheckConstraint(
            sql_in("status", DISPOSITION_STATUSES), name="ck_finding_disposition_status"
        ),
    )

    def __repr__(self) -> str:
        return f"<FindingDisposition {self.status} {self.fingerprint[:8]}>"
