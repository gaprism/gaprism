# Epic 07: Data Retention & Operational Hardening (Milestone M7)

**Epic Owner**: Platform Operations & Data Governance  
**Target Milestone**: M7 Lifecycle and Operations  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-09**: Access expires at the policy deadline even if physical deletion is delayed.

---

## 1. Epic Overview

The objective of Epic 07 is to implement strict calendar-month retention calculators, automated daily batch purging of expired evidence, administrative retention holds, backup/restore deletion journal replay, and comprehensive operational runbooks.

---

## 2. Stories Breakdown

### Story 7.1: Calendar-Month Retention Clocks & Daily Purge
- **Goal**: Implement 12-calendar-month UTC expiry calculators with leap-day clamping and automated idempotent purge tasks.
- **Invariants Enforced**: INV-09
- **Technical Contracts**:
  - `app/service/evidence/retention.py`:
    - `calculate_calendar_expiry(anchor_time: datetime, months: int = 12) -> datetime`:
      - Preserves UTC hour/minute/second.
      - Clamps invalid end-of-month days: `2028-02-29 + 12 months -> 2029-02-28 23:59:59 UTC` (**RET-01**).
    - Policy evaluation immediately blocks reads for expired records even before physical deletion occurs (INV-09, **RET-01**).
  - `app/service/evidence/purge.py`:
    - `execute_daily_purge_job(batch_size: int = 500) -> PurgeReport`:
      - Queries expired unheld `ScanRun`, `CheckResult`, `Artifact`, `ReportVersion`.
      - Deletes physical files via `StorageDriver.delete()`.
      - Removes database records within short transactions.
      - Idempotent: handles missing files without crashing.
- **Acceptance Criteria**:
  - Leap year edge cases clamp correctly without generating invalid date exceptions (**RET-01**).
  - Expired scans and artifacts return HTTP 404/410 to all user queries before purge runs (**RET-01**).
  - Physical files and database rows are purged completely in batches.
- **Definition of Done (DoD)**:
  - [ ] Retention calculator and purge runner implemented in `app/service/evidence/`.
  - [ ] Retention clock tests **RET-01** passing in `tests/lifecycle/test_retention.py`.
  - [ ] Type checks pass (`mypy --strict app/service/evidence/retention.py app/service/evidence/purge.py`).

---

### Story 7.2: Administrative Holds & Backup/Restore Deletion Replay
- **Goal**: Implement administrative legal holds and a deletion journal to replay purges upon database restoration from backup snapshots.
- **Invariants Enforced**: INV-09
- **Technical Contracts**:
  - `app/models/retention.py`:
    - `RetentionHold`: `id`, `target_type: ['assessment', 'report']`, `target_id: UUID`, `reason: str`, `created_by_id`, `expires_at: datetime | None`.
    - `DeletionJournal`: `id`, `entity_type: str`, `entity_id: UUID`, `deleted_at: datetime`.
  - `app/service/evidence/restore_replay.py`:
    - `replay_deletion_journal(db_session, storage: StorageDriver) -> ReplayResult`:
      - Reads `DeletionJournal` table to identify entities that were deleted prior to backup restoration.
      - Re-purges restored rows and re-deletes restored artifact files (**OPS-01**).
- **Acceptance Criteria**:
  - Active retention holds prevent physical deletion and access expiry of associated records.
  - Executing the deletion replay script after restoring an old backup cleans up previously purged entities (**OPS-01**).
- **Definition of Done (DoD)**:
  - [ ] `RetentionHold` and `DeletionJournal` models implemented.
  - [ ] Backup restoration drill test **OPS-01** passing in `tests/lifecycle/test_restore_replay.py`.
  - [ ] Type checks pass (`mypy --strict app/service/evidence/restore_replay.py`).

---

### Story 7.3: Operator Runbook & Production Hardening
- **Goal**: Author comprehensive operator runbooks for system bootstrapping, secret rotation, worker lease reclamation, quota recovery, and disaster recovery.
- **Invariants Enforced**: INV-09, INV-12
- **Technical Contracts**:
  - `docs/operations/runbook.md`:
    - Initial Admin User Onboarding & MFA Bootstrap CLI.
    - Secret Rotation: `SECRET_KEY`, `MFA_ENCRYPTION_KEY`, database credentials.
    - Quota & Worker Lease Troubleshooting (manual generation increment and lease break).
    - Offline Playwright Renderer Container Setup.
    - Disaster Recovery: PostgreSQL snapshot restoration and `DeletionJournal` replay drill execution (**OPS-01**).
  - `docker-compose.yml`:
    - Local multi-container development configuration: Flask web, coordinator worker, isolated runner, PostgreSQL 16.
- **Acceptance Criteria**:
  - Operator runbook provides exact, non-destructive CLI instructions for all key maintenance tasks.
  - Docker Compose environment boots up services cleanly with isolated network bridging.
- **Definition of Done (DoD)**:
  - [ ] `docs/operations/runbook.md` authored.
  - [ ] `docker-compose.yml` configured and verified.
