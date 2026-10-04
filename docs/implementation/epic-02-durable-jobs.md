# Epic 02: Durable Job Queue & Quota Accounting (Milestone M2)

**Epic Owner**: Background Engine & Persistence  
**Target Milestone**: M2 Durable Execution  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-04**: No data, no match, not licensed and collection failure are distinct outcomes.
- **INV-08**: Retrying jobs cannot create duplicate logical observations or accept stale worker results.

---

## 1. Epic Overview

The objective of Epic 02 is to build a reliable, lightweight transactional job queue within PostgreSQL using `SELECT ... FOR UPDATE SKIP LOCKED`. It manages background task execution, worker lease heartbeat renewals, generation fencing (`generation_id`), API quota reservations (for CT, Shodan, Web Risk), and race-free scan run lifecycle finalisation and cancellation.

---

## 2. Stories Breakdown

### Story 2.1: Transactional Queue State Machine
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Lease expiry, generation fencing, concurrent claims, and crash recovery are complex but well-specified transactional state-machine work.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if concurrency tests expose an unclear linearisation point or stale-write path.
- **Goal**: Implement `Job` and `JobAttempt` models with lease-based claiming, generation fencing, and crash recovery.
- **Invariants Enforced**: INV-08
- **Technical Contracts**:
  - `app/models/job.py`:
    - `Job`: `id`, `run_id`, `job_type`, `payload: dict`, `status: ['queued', 'running', 'completed', 'failed', 'cancelled']`, `idempotency_key: str`, `lease_owner: str | None`, `lease_expires_at: datetime | None`, `generation_id: int`, `attempts: int`, `max_attempts: int`.
    - `JobAttempt`: `id`, `job_id`, `started_at`, `finished_at`, `status`, `error_message`, `worker_host`.
  - `app/service/jobs/queue.py`:
    - `claim_jobs(worker_id: str, batch_size: int, lease_duration: timedelta) -> list[Job]`:
      - SQL: `SELECT * FROM job WHERE status = 'queued' OR (status = 'running' AND lease_expires_at < NOW()) ORDER BY priority, created_at LIMIT :batch_size FOR UPDATE SKIP LOCKED;`
      - Updates `status = 'running'`, sets `lease_owner = :worker_id`, `lease_expires_at = NOW() + :lease_duration`, increments `generation_id`.
    - `heartbeat(job_id: UUID, worker_id: str, generation_id: int, lease_duration: timedelta) -> bool`.
    - `complete_job(job_id: UUID, worker_id: str, generation_id: int, results: dict) -> bool`: Rejects write if `generation_id` in DB does not match worker's generation.
- **Acceptance Criteria**:
  - Multiple concurrent worker threads claim mutually exclusive job batches without deadlock.
  - A worker crashing midway allows a subsequent worker to reclaim the expired lease (**JOB-01**).
  - A slow worker attempting to complete a job after its lease has expired and been reassigned is rejected with a generation fencing error (**JOB-02**).
- **Definition of Done (DoD)**:
  - [ ] Job models and queue service implemented in `app/service/jobs/`.
  - [ ] Concurrency and crash recovery integration tests in `tests/jobs/test_queue.py` passing **JOB-01** and **JOB-02**.
  - [ ] Strict type checking passes (`mypy --strict app/service/jobs/`).

---

### Story 2.2: Quota Ledger & Rate Limiting
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Quota reservation has transactional and temporal edge cases, while its bounded state model makes Sol the cost-effective default.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) for unresolved cross-window accounting or provider-contract ambiguity.
- **Goal**: Implement pre-call API quota reservation and consumption accounting to avoid exceeding third-party provider limits.
- **Invariants Enforced**: INV-04
- **Technical Contracts**:
  - `app/models/quota.py`:
    - `ProviderQuota`: `provider: ['ct', 'shodan', 'webrisk', 'geoip']`, `period: ['minute', 'day', 'month']`, `limit: int`, `used: int`, `reset_at: datetime`.
    - `QuotaReservation`: `id`, `job_id`, `provider`, `amount: int`, `status: ['reserved', 'committed', 'released']`.
  - `app/service/jobs/quota.py`:
    - `reserve_quota(provider: str, amount: int, job_id: UUID) -> QuotaReservation | None`.
    - `commit_quota(reservation_id: UUID) -> None`.
    - `release_quota(reservation_id: UUID) -> None`.
  - When quota is exhausted, transitions job/run state to `waiting_provider` without crashing or spinning CPU.
- **Acceptance Criteria**:
  - Worker cannot invoke Shodan/WebRisk API without a committed reservation.
  - Quota exhaustion pauses task dispatch and schedules a delayed retry after `reset_at`.
  - Worker failure releases unused quota reservations back to the ledger.
- **Definition of Done (DoD)**:
  - [ ] Quota models and ledger service implemented.
  - [ ] Unit tests simulating quota exhaustion and release on failure in `tests/jobs/test_quota.py`.
  - [ ] Type checks pass (`mypy --strict app/service/jobs/quota.py`).

---

### Story 2.3: Scan Run Lifecycle & Cancellation
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Run finalisation and cancellation involve race conditions and dynamic child jobs, fitting Sol's complex coding profile.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if JOB-03 cannot establish a single safe transaction boundary.
- **Goal**: Implement scan run state progression, dynamic child job tracking, and graceful scan cancellation.
- **Invariants Enforced**: INV-08
- **Technical Contracts**:
  - `app/models/scan_run.py`:
    - `ScanRun`: `id`, `assessment_id`, `status: ['queued', 'running', 'completed', 'partial', 'cancelled', 'failed']`, `target_domain: str`, `total_hosts_discovered: int`, `started_at`, `completed_at`, `cancellation_reason: str | None`.
  - `app/service/assessment/run_manager.py`:
    - `start_run(assessment_id: UUID, actor: ActorContext) -> ScanRun`.
    - `cancel_run(run_id: UUID, actor: ActorContext, reason: str) -> None`: Marks run `cancelled`, updates pending jobs to `cancelled`, and signals active workers.
    - `check_and_finalize_run(run_id: UUID) -> ScanRun`:
      - SQL lock on `ScanRun` row to prevent race conditions where child jobs are inserted simultaneously (**JOB-03**).
- **Acceptance Criteria**:
  - Cancelling a run terminates in-flight jobs gracefully, marks the run `cancelled`, and retains all observations collected up to the cancellation point.
  - Finalisation check does not mark a run `completed` if another worker is currently inserting child discovery jobs (**JOB-03**).
- **Definition of Done (DoD)**:
  - [ ] Run state machine and cancellation logic implemented.
  - [ ] Test **JOB-03** (finalisation race condition under load) passing in `tests/jobs/test_run_lifecycle.py`.
  - [ ] Type checks pass (`mypy --strict app/service/assessment/`).
