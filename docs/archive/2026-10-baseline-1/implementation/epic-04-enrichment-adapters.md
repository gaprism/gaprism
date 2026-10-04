# Epic 04: Host Verification & Enrichment Adapters (Milestone M4)

**Epic Owner**: Target Inspection & Data Enrichment  
**Target Milestone**: M4 Required Enrichment  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-03**: Every collected fact identifies its subject, source, time, and collection method.
- **INV-04**: No data, no match, not licensed and collection failure are distinct outcomes.
- **INV-05**: A CT entry is not live TLS validation; an IP observation is not automatic hostname attribution.
- **INV-06**: All target traffic crosses enforced public-only egress; target execution holds no application credentials.

---

## 1. Epic Overview

The objective of Epic 04 is to implement active endpoint verification (live TLS validation), an isolated Playwright screenshot sandbox supervisor, and passive enrichment adapters (GeoIP/ASN, Shodan IP ports/CVEs, Google Web Risk URL reputation). It establishes typed outcome classifications ensuring provider errors and licensing limitations are explicitly recorded without generating false security verdicts.

---

## 2. Stories Breakdown

### Story 4.1: Live TLS Endpoint Prober
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: TLS validation combines network pinning, certificate semantics, failure classification, and evidence capture, but has clear protocol contracts.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if verification and forensic metadata collection cannot be separated safely.
- **Goal**: Probe HTTPS endpoints to record certificate trust chains, SAN coverage, validity dates, and cipher suites, skipping dependent active checks on TLS failure.
- **Invariants Enforced**: INV-03, INV-05
- **Technical Contracts**:
  - `runner/tls.py`:
    - `probe_tls_endpoint(hostname: str, port: int = 443, ip_override: str | None = None) -> TLSProbeResult`:
      - Validates CA trust chain against standard root store (Mozilla/system).
      - Checks SAN (Subject Alternative Name) match against target hostname.
      - Checks certificate validity window (`not_before`, `not_after`).
      - Records exact failure reasons (`CERTIFICATE_VERIFY_FAILED`, `HOSTNAME_MISMATCH`, `CERTIFICATE_EXPIRED`).
      - Does NOT fall back to `verify=False` under any circumstances (**COL-02**).
  - On TLS failure, the coordinator records the failed TLS result and marks downstream HTTP metadata and screenshot jobs as `skipped_due_to_tls_failure`.
- **Acceptance Criteria**:
  - Expired, self-signed, or name-mismatched certificates are recorded with their explicit failure reason (**COL-02**).
  - Valid wildcard certificates are validated correctly for matching subdomains without enumerating sibling names.
  - TLS failures halt active HTTP exploration on the endpoint.
- **Definition of Done (DoD)**:
  - [ ] `runner/tls.py` and `app/service/checks/tls.py` implemented.
  - [ ] Unit & integration tests **COL-02** passing in `tests/checks/test_tls.py`.
  - [ ] Type checks pass (`mypy --strict runner/tls.py app/service/checks/tls.py`).

---

### Story 4.2: Isolated Screenshot Sandbox Supervisor
- **Coding-agent model**: `gpt-6-astra` with reasoning effort `xhigh`.
- **Price/performance rationale**: Executing an untrusted page crosses process, browser, DNS, network, filesystem, and resource-isolation boundaries; route interception alone is insufficient.
- **Escalation rule**: Keep Astra for the sandbox architecture and escape analysis. Sol may implement approved container/proxy plumbing and deterministic tests.
- **Goal**: Execute isolated Playwright Chromium screenshot capture within strict resource, timeout, and egress ceilings.
- **Invariants Enforced**: INV-06
- **Technical Contracts**:
  - `runner/browser.py`:
    - `capture_screenshot(url: str, pinned_ip: str, timeout_seconds: int = 30) -> ScreenshotResult`:
      - Headless Chromium with sandboxing enabled (`--no-sandbox` prohibited).
      - Disposable browser profile, no stored cookies, no persisted local storage.
      - Fixed viewport proposal: `1440x900`.
      - Bounded settle time (DOM ready + 2s settle; unlimited `networkidle` prohibited).
      - Memory ceiling (512MB limit) and execution timeout (30 seconds).
      - Non-HTML endpoints (e.g. JSON APIs, binary streams) detected via `Content-Type` header and marked `not_applicable` without capturing.
      - Playwright sandboxes run without database connection strings or cloud credentials in environment (**NET-02**).
- **Acceptance Criteria**:
  - Screenshots render successfully into PNG format and are staged for storage.
  - Target pages cannot access internal management ports, cloud metadata, or Docker sockets (**NET-02**).
  - Malformed or hanging web pages time out cleanly without leaking worker processes.
- **Definition of Done (DoD)**:
  - [ ] `runner/browser.py` implemented.
  - [ ] Sandbox isolation and memory limit tests **NET-02** passing in `tests/runner/test_browser.py`.
  - [ ] Type checks pass (`mypy --strict runner/browser.py`).

---

### Story 4.3: GeoIP, Shodan & Reputation Adapters
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `high`.
- **Price/performance rationale**: Three provider contracts, attribution confidence, licensing states, and malformed-response handling need strong integration reasoning at a controlled scope.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) if provider evidence could be misattributed to the assessed SaaS.
- **Goal**: Implement MaxMind/IP2Location local reader, Shodan IP-level queries, and Google Web Risk URL reputation lookup with strict attribution and error typing.
- **Invariants Enforced**: INV-04, INV-05
- **Technical Contracts**:
  - `app/service/checks/geoip.py`:
    - `lookup_geoip(ip: str) -> GeoIPResult`: Reads local MaxMind GeoLite2/GeoIP database; returns ISO country code, country name, ASN, and organisation.
  - `app/service/checks/shodan.py`:
    - `lookup_shodan_host(ip: str) -> ShodanHostResult`:
      - Queries Shodan IP endpoint; extracts open ports, transport protocols, banners, and reported CVEs.
      - Attribution rule: CVEs observed on shared IP/CDN are explicitly marked `attribution: "shared_infrastructure"` or `"ip_only"`, never attributed to hostname without verification (**FIND-01**).
  - `app/service/checks/webrisk.py`:
    - `lookup_threat_uri(url: str) -> ThreatLookupResult`: Queries Google Web Risk lookup API; reports threat types (`MALWARE`, `SOCIAL_ENGINEERING`).
  - Strict outcome classification across all adapters:
    - Distinguishes: `succeeded: no_match`, `succeeded: match`, `unlicensed`, `quota_exhausted`, `timeout`, `provider_error` (**PRV-01**).
- **Acceptance Criteria**:
  - Provider 401, 403, 404, 429, and timeouts are returned as typed diagnostic statuses rather than silent empty arrays (**PRV-01**).
  - Shodan CVEs on CDN/shared hosting are attributed to infrastructure rather than target hostname (**FIND-01**).
- **Definition of Done (DoD)**:
  - [ ] GeoIP, Shodan, and WebRisk adapters implemented in `app/service/checks/`.
  - [ ] Adapter error classification tests **PRV-01** and attribution tests **FIND-01** passing in `tests/checks/test_adapters.py`.
  - [ ] Type checks pass (`mypy --strict app/service/checks/`).
