# Epic 06: Evidence Storage & Bilingual Reporting (Milestone M6)

**Epic Owner**: Evidence Management & Reporting Engine  
**Target Milestone**: M6 Evidence and Reports  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-02**: Report-only access never grants underlying case, job, host, or raw-artifact access.
- **INV-07**: Issued report content and artifact bytes never change; corrections create a new version.
- **INV-10**: DE and EN reports describe identical facts; raw evidence is preserved in its source language.
- **INV-11**: Export/download is not proof of confirmed TPRM transfer.

---

## 1. Epic Overview

The objective of Epic 06 is to build a secure, private artifact storage driver, a deterministic canonical JSON snapshot builder, an offline bilingual (`en` and `de-CH`) PDF report renderer with cryptographic SHA-256 manifests, and a manual TPRM handoff audit logger.

---

## 2. Stories Breakdown

### Story 6.1: Storage Driver & Staging Lifecycle
- **Goal**: Implement `StorageDriver` interface with private filesystem backend, atomic staging, SHA-256 verification, and path traversal rejection.
- **Invariants Enforced**: INV-07
- **Technical Contracts**:
  - `app/service/evidence/storage.py`:
    - `StorageDriver` ABC:
      - `stage(stream: BinaryIO, max_bytes: int, expected_type: str) -> StagingRef`.
      - `commit(stage_ref: StagingRef, artifact_id: UUID) -> ArtifactMetadata`: Computes SHA-256, verifies byte count, atomically renames to final private path.
      - `open(locator: str, version: str) -> BinaryIO`: Authorised streaming read outside web root.
      - `verify(locator: str, expected_hash: str, expected_bytes: int) -> bool`.
      - `delete(locator: str, version: str) -> bool`: Idempotent physical deletion.
  - Security constraints:
    - Files stored strictly outside web root (`/var/data/evidence/`).
    - Random UUID paths prevent directory traversal attacks (`../` rejected) (**EVD-01**).
    - Integrity mismatch raises `CorruptedArtifactError`.
- **Acceptance Criteria**:
  - Directory traversal attempts in file names or locators are rejected (**EVD-01**).
  - Staging failures clean up partial files without creating dangling locks (**EVD-01**).
  - Committed files are marked read-only at the filesystem level.
- **Definition of Done (DoD)**:
  - [ ] `StorageDriver` interface and `FilesystemStorageDriver` implemented.
  - [ ] Storage integration tests **EVD-01** passing in `tests/evidence/test_storage.py`.
  - [ ] Type checks pass (`mypy --strict app/service/evidence/storage.py`).

---

### Story 6.2: Canonical Report Snapshot Builder
- **Goal**: Serialise assessment run facts, findings, and evidence references into deterministic, canonical UTF-8 JSON with immutable hash binding.
- **Invariants Enforced**: INV-07
- **Technical Contracts**:
  - `app/service/reporting/snapshot.py`:
    - `build_canonical_snapshot(assessment_id: UUID, run_id: UUID, actor: ActorContext) -> tuple[dict, str]`:
      - Gathers: canonical scope, summary cards facts, host inventory, findings, annotations as of cutoff, and evidence copy mappings.
      - Encodes to canonical JSON (sorted keys, compact delimiters `,` and `:`, UTC ISO 8601 timestamps, stable array sorting).
      - Computes SHA-256 `snapshot_hash`.
  - `app/models/report.py`:
    - `ReportVersion`: `id`, `assessment_id`, `version_number: int`, `status: ['draft', 'approved', 'issued', 'superseded']`, `snapshot_hash: str`, `snapshot_data: dict`, `prepared_by_id`, `approved_by_id | None`, `issued_at | None`.
  - Four-eyes review check: approval is cryptographically tied to `snapshot_hash`; modifying findings invalidates prior approvals (**REP-01**).
- **Acceptance Criteria**:
  - Snapshot JSON serialization is 100% deterministic (identical hash for identical data across platforms) (**REP-01**).
  - Rerunning a scan or editing notes does not alter already issued report snapshots (**REP-01**).
- **Definition of Done (DoD)**:
  - [ ] Snapshot builder and report version models implemented.
  - [ ] Immutability tests **REP-01** passing in `tests/reporting/test_snapshot.py`.
  - [ ] Type checks pass (`mypy --strict app/service/reporting/snapshot.py`).

---

### Story 6.3: Bilingual PDF Renderer & Manifest Generator
- **Goal**: Render offline, defensible PDF reports in English (`en`) and Swiss Standard German (`de-CH`) via Playwright and generate cryptographic SHA-256 manifests.
- **Invariants Enforced**: INV-02, INV-07, INV-10
- **Technical Contracts**:
  - `app/service/reporting/renderer.py`:
    - `render_report_pdf(snapshot: dict, locale: Literal['en', 'de-CH']) -> tuple[bytes, str]`:
      - Offline Playwright browser renderer (zero outbound network requests during rendering).
      - Jinja templates with Babel message catalogs: Swiss Standard German (`de-CH` with correct umlauts and `ss`, no `ß`).
      - Inlines evidence figures, screenshots, and finding severity tables.
      - Guarantees identical facts, finding IDs, and severity counts across both locales (**LNG-01**).
  - `app/service/reporting/manifest.py`:
    - Generates `manifest.json` recording: `snapshot_hash`, PDF hashes for each locale, template version, and timestamp.
  - Report-only recipient isolation:
    - Grant recipients with `ReportGrant` can download only the PDF/manifest for their exact version and cannot access raw case artifacts (**REP-02**).
- **Acceptance Criteria**:
  - `en` and `de-CH` PDFs generated from the same snapshot contain identical technical facts and finding counts (**LNG-01**).
  - Report-only users receive HTTP 403/404 when attempting to access underlying host inventory or raw scanner artifacts (**REP-02**).
- **Definition of Done (DoD)**:
  - [ ] PDF renderer and bilingual templates implemented in `templates/reports/`.
  - [ ] Parity test **LNG-01** and isolation test **REP-02** passing in `tests/reporting/test_renderer.py`.
  - [ ] Type checks pass (`mypy --strict app/service/reporting/`).

---

### Story 6.4: Manual TPRM Handoff Logger
- **Goal**: Implement manual transfer confirmation logging to track TPRM handoffs with external ticket references.
- **Invariants Enforced**: INV-11
- **Technical Contracts**:
  - `app/models/handoff.py`:
    - `TPRMHandoff`: `id`, `report_version_id`, `actor_id`, `tprm_reference: str`, `destination_system: str`, `confirmed_at: datetime`, `notes: str | None`.
  - `app/service/reporting/handoff.py`:
    - `record_tprm_handoff(report_version_id: UUID, tprm_reference: str, actor: ActorContext) -> TPRMHandoff`:
      - Appends handoff event.
      - Downloading a report does NOT automatically mark TPRM handoff as confirmed (INV-11).
  - UI displays explicit status badges: `Handoff Confirmed (Ref: TPRM-1234)` or `Unconfirmed Handoff Warning`.
- **Acceptance Criteria**:
  - Downloading a PDF leaves the handoff state unconfirmed until explicit analyst confirmation.
  - Handoff logs record the user, timestamp, report version, and external ticket reference.
- **Definition of Done (DoD)**:
  - [ ] TPRM handoff models, routes, and UI forms implemented.
  - [ ] Unit tests in `tests/reporting/test_handoff.py`.
  - [ ] Type checks pass (`mypy --strict app/service/reporting/handoff.py`).
