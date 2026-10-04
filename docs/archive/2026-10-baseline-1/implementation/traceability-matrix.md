# Requirements & Invariant Traceability Matrix

This matrix maps all Acceptance Tests (ACC-01 through PERF-01) and Cross-Cutting Invariants (INV-01 through INV-12) to their implementing Epics, Stories, and verification test suites.

---

## 1. Cross-Cutting Invariants Traceability

| Invariant ID | Description | Implementing Stories | Automated Verification Suites |
|---|---|---|---|
| **INV-01** | A role never grants access to an unrelated assessment. | Story 1.2, Story 1.3 | `tests/access/test_matrix.py`, `tests/access/test_rls.py` |
| **INV-02** | Report-only access never grants underlying case, job, host, or raw-artifact access. | Story 1.2, Story 1.3, Story 6.3 | `tests/access/test_matrix.py`, `tests/reporting/test_renderer.py` |
| **INV-03** | Every collected fact identifies its subject, source, time, and collection method. | Story 3.2, Story 4.1, Story 5.1, Story 5.3 | `tests/checks/test_adapters.py`, `tests/reporting/test_snapshot.py` |
| **INV-04** | No data, no match, not licensed and collection failure are distinct outcomes. | Story 2.2, Story 4.3, Story 5.1 | `tests/jobs/test_quota.py`, `tests/checks/test_adapters.py` |
| **INV-05** | A CT entry is not live TLS validation; an IP observation is not automatic hostname attribution. | Story 3.2, Story 4.1, Story 4.3 | `tests/discovery/test_ct.py`, `tests/checks/test_tls.py`, `tests/checks/test_adapters.py` |
| **INV-06** | All target traffic crosses enforced public-only egress; target execution holds no application credentials. | Story 3.1, Story 3.3, Story 4.2 | `tests/discovery/test_scope.py`, `tests/runner/test_ssrf_gate.py`, `tests/runner/test_browser.py` |
| **INV-07** | Issued report content and artifact bytes never change; corrections create a new version. | Story 5.3, Story 6.1, Story 6.2, Story 6.3 | `tests/evidence/test_storage.py`, `tests/reporting/test_snapshot.py` |
| **INV-08** | Retrying jobs cannot create duplicate logical observations or accept stale worker results. | Story 2.1, Story 2.3, Story 6.2 | `tests/jobs/test_queue.py`, `tests/jobs/test_run_lifecycle.py` |
| **INV-09** | Access expires at the policy deadline even if physical deletion is delayed. | Story 1.2, Story 7.1, Story 7.2 | `tests/lifecycle/test_retention.py`, `tests/lifecycle/test_restore_replay.py` |
| **INV-10** | DE and EN reports describe identical facts; raw evidence is preserved in its source language. | Story 6.3 | `tests/reporting/test_renderer.py` |
| **INV-11** | Export/download is not proof of confirmed TPRM transfer. | Story 6.4 | `tests/reporting/test_handoff.py` |
| **INV-12** | No network work, scheduler, or migration starts as an import-time side effect. | Story 0.1, Story 0.2, Story 0.3, Story 7.3 | `tests/test_factory.py`, `tests/test_migrations.py` |

---

## 2. Acceptance Test Matrix Traceability

| Test ID | Test Area | Scenario Description | Primary Story | Verification Module |
|---|---|---|---|---|
| **ACC-01** | Authorisation | 2-case, 5-role permission matrix validation; foreign scope access returns 404/403. | Story 1.2 | `tests/access/test_matrix.py` |
| **ACC-02** | Database RLS | PostgreSQL RLS prevents tenant cross-talk across pooled connections without connection reset. | Story 1.3 | `tests/access/test_rls.py` |
| **COL-01** | Discovery | CT log parser handles cursor pagination, duplicates, empty results, and wildcards. | Story 3.2 | `tests/discovery/test_ct.py` |
| **COL-02** | TLS Endpoint | Failed/expired/mismatched TLS recorded with failure reason; skips active HTTP collection. | Story 4.1 | `tests/checks/test_tls.py` |
| **NET-01** | SSRF Gate | DNS resolution and HTTP requests to private, loopback, and cloud metadata (169.254.169.254) blocked. | Story 3.3 | `tests/runner/test_ssrf_gate.py` |
| **NET-02** | Sandbox Egress | Browser sandboxes cannot access internal application networks or bypass egress proxies. | Story 4.2 | `tests/runner/test_browser.py` |
| **JOB-01** | Job Recovery | Worker crash recovery and at-most-one accepted logical result via generation fencing. | Story 2.1 | `tests/jobs/test_queue.py` |
| **JOB-02** | Concurrency | Stale lease workers rejected upon lease expiration and reassignment. | Story 2.1 | `tests/jobs/test_queue.py` |
| **JOB-03** | Finalisation Race | Run finalisation locked against concurrent child job insertions. | Story 2.3 | `tests/jobs/test_run_lifecycle.py` |
| **PRV-01** | Provider Errors | 401, 403, 404, 429, timeout, and malformed responses classified without false `no_match`. | Story 4.3 | `tests/checks/test_adapters.py` |
| **FIND-01** | Attribution | Shodan CVEs on shared hosting/CDNs marked `shared_infrastructure` / `ip_only`. | Story 4.3 | `tests/checks/test_adapters.py` |
| **EVD-01** | Storage Driver | Directory traversal rejected; staging failures handled; SHA-256 hashes verified. | Story 6.1 | `tests/evidence/test_storage.py` |
| **REP-01** | Report Immutability | Re-running scans or modifying notes does not alter issued snapshots or PDFs. | Story 6.2 | `tests/reporting/test_snapshot.py` |
| **REP-02** | Report Isolation | Report-only recipients access only their exact version; raw scan artifacts inaccessible. | Story 6.3 | `tests/reporting/test_renderer.py` |
| **LNG-01** | Bilingual Parity | English and Swiss Standard German (`de-CH`) PDFs contain identical finding counts and facts. | Story 6.3 | `tests/reporting/test_renderer.py` |
| **RET-01** | Retention Clocks | 12-month retention expiry with leap-day clamping (`Feb 29 -> Feb 28`); expired reads denied. | Story 7.1 | `tests/lifecycle/test_retention.py` |
| **OPS-01** | Disaster Recovery | Backup restoration drill successfully replays deletion journal to purge expired records. | Story 7.2 | `tests/lifecycle/test_restore_replay.py` |
| **UX-01** | Accessibility | Full assessment creation, filtering, and report export workflow operable via keyboard only. | Story 5.2 | `tests/ui/test_accessibility.py` |
| **PERF-01** | Performance | 1,000-host scan query and pagination renders within 200ms. | Story 5.2 | `tests/performance/test_host_table.py` |
