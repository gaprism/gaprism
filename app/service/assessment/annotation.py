"""Analyst annotation service with optimistic concurrency control."""

from __future__ import annotations

import uuid

from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.extensions import db
from app.models.annotation import FindingAnnotation
from app.models.assessment import Assessment
from app.models.check import Finding
from app.service.access.context import ActorContext
from app.service.access.permission_evaluator import ActionEnum, check_permission


class OptimisticLockConflictError(Exception):
    """Raised when an annotation edit is attempted against a stale version."""

    def __init__(self, current_version: int, expected_version: int) -> None:
        super().__init__(
            f"Version conflict: current version is {current_version}, but {expected_version} was expected."
        )
        self.current_version = current_version
        self.expected_version = expected_version


class AnnotationSchema(BaseModel):
    """Payload schema for creating or revising a finding annotation."""

    model_config = ConfigDict(strict=True)

    justification: str = Field(..., min_length=1, max_length=5000)
    revised_severity: str | None = Field(
        default=None,
        pattern=r"^(informational|low|medium|high|critical)$",
    )
    is_false_positive: bool = False


def create_or_update_annotation(
    finding_id: uuid.UUID,
    data: AnnotationSchema,
    expected_version: int,
    actor: ActorContext,
    session: Session | None = None,
) -> FindingAnnotation:
    """Create or update a finding annotation enforcing optimistic locking and permissions."""
    s = session or db.session
    finding = s.scalar(select(Finding).where(Finding.id == finding_id))
    if finding is None:
        raise ValueError(f"Finding {finding_id} not found.")

    # Validate analyst / owner permission
    assessment = s.scalar(
        select(Assessment).where(Assessment.id == finding.assessment_id)
    )
    if not check_permission(actor, assessment, ActionEnum.ADD_TECHNICAL_ANNOTATION, session=s):
        raise PermissionError("User not authorized to add technical annotations.")

    # Check for existing annotation on this finding
    stmt = select(FindingAnnotation).where(
        FindingAnnotation.finding_id == finding_id,
        FindingAnnotation.assessment_id == finding.assessment_id,
    )
    annotation = s.scalar(stmt)

    if annotation is None:
        # Initial creation: expected_version should be 1
        if expected_version != 1:
            raise OptimisticLockConflictError(current_version=1, expected_version=expected_version)

        annotation = FindingAnnotation(
            workspace_id=finding.workspace_id,
            assessment_id=finding.assessment_id,
            finding_id=finding.id,
            author_id=actor.user_id,
            justification=data.justification.strip(),
            revised_severity=data.revised_severity,
            is_false_positive=data.is_false_positive,
            version_id=1,
        )
        s.add(annotation)
    else:
        # Optimistic locking check
        if annotation.version_id != expected_version:
            raise OptimisticLockConflictError(
                current_version=annotation.version_id,
                expected_version=expected_version,
            )

        annotation.justification = data.justification.strip()
        annotation.revised_severity = data.revised_severity
        annotation.is_false_positive = data.is_false_positive
        annotation.author_id = actor.user_id
        annotation.version_id += 1

    s.flush()
    return annotation
