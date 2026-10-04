# Epic 03: Scope Normalisation & Discovery Network Gate (Milestone M3)

**Epic Owner**: Discovery & Network Security  
**Target Milestone**: M3 Discovery and Network Gate  
**Status**: Ready for Implementation  
**Key Invariants Enforced**:
- **INV-03**: Every collected fact identifies its subject, source, time, and collection method.
- **INV-05**: A CT entry is not live TLS validation; an IP observation is not automatic hostname attribution.
- **INV-06**: All target traffic crosses enforced public-only egress; target execution holds no application credentials.

---

## 1. Epic Overview

The objective of Epic 03 is to establish rigorous input sanitisation, Certificate Transparency (CT) log discovery with cursor pagination, and a strict Anti-SSRF / DNS pinning egress gate. This ensures that only valid, public domain scopes are assessed and target traffic can never probe private, internal, loopback, or cloud metadata networks.

---

## 2. Stories Breakdown

### Story 3.1: Scope Normaliser & Public Suffix Screening
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `medium`.
- **Price/performance rationale**: Domain normalisation and PSL handling are precise standards work with strong fixture-based verification and moderate implementation complexity.
- **Escalation rule**: Escalate to `gpt-6-astra` (`high`) only for unresolved IDNA/PSL security boundary cases.
- **Goal**: Implement deterministic domain scope canonicalisation, IDNA translation, and Public Suffix List (PSL) rejection.
- **Invariants Enforced**: INV-06
- **Technical Contracts**:
  - `app/service/discovery/scope.py`:
    - `canonicalise_domain(raw_input: str) -> DomainScope`:
      - Strips whitespace and trailing dot.
      - Converts IDNA to ASCII lowercase (`xn--...`).
      - Validates total length (<= 253 chars) and label lengths (<= 63 chars).
      - Rejects: URL syntax (`https://...`), paths, ports, userinfo, IP literals (IPv4/IPv6), wildcard input (`*.example.com`), and empty labels.
      - Rejects public suffixes (e.g. `co.uk`, `com`, `github.io`) using a local snapshot of the Public Suffix List.
    - `is_in_scope(hostname: str, scope: DomainScope) -> bool`:
      - Strict dot-boundary enforcement: `sub.target.com` and `target.com` are in scope; `nottarget.com` and `target.com.evil.com` are rejected.
- **Acceptance Criteria**:
  - Valid internationalised domain names (e.g. `münchen.de`) canonicalise accurately to ASCII `xn--mnchen-3ya.de`.
  - Inputting IP addresses, protocol schemes, port numbers, or public suffixes returns explicit HTTP 400 validation errors.
  - Subdomain boundary check prevents false match across domain name substrings.
- **Definition of Done (DoD)**:
  - [ ] `app/service/discovery/scope.py` implemented.
  - [ ] Comprehensive boundary unit tests in `tests/discovery/test_scope.py`.
  - [ ] Type checks pass (`mypy --strict app/service/discovery/scope.py`).

---

### Story 3.2: CT Log Discovery Adapter
- **Coding-agent model**: `gpt-6.1-sol` with reasoning effort `medium`.
- **Price/performance rationale**: The CT adapter is a bounded external-API integration with pagination, quotas, deduplication, and explicit response contracts.
- **Escalation rule**: Use `gpt-6-luna` (`high`) for additional provider fixture cases; escalate to Astra only if source attribution rules change.
- **Goal**: Query Certificate Transparency logs via cursor pagination, deduplicate hostnames, retain wildcard patterns, and enforce run host caps.
- **Invariants Enforced**: INV-03, INV-05
- **Technical Contracts**:
  - `app/service/discovery/ct.py`:
    - `CTDiscoveryAdapter`:
      - `fetch_page(domain: str, cursor: str | None = None) -> CTPagedResult`.
      - Rate limiting and usage tracking coordinated via `QuotaReservation`.
      - Deduplicates discovered hostnames.
      - Wildcards (e.g. `*.example.com`) stored as wildcard pattern metadata, never converted to concrete DNS hosts (INV-05).
      - Atomic persistence: each page commit inserts new hosts and schedules subsequent child jobs.
      - Enforces host cap (`MAX_HOSTS_PER_RUN = 1000`) and page cap (`MAX_DISCOVERY_PAGES = 50`); marks discovery `partial` if cap is exceeded.
- **Acceptance Criteria**:
  - Paged discovery processes multi-page responses and follows opaque cursors cleanly (**COL-01**).
  - Empty or single-result CT lookups succeed without crashing.
  - Hitting host caps halts further scheduling and records a partial coverage notice.
- **Definition of Done (DoD)**:
  - [ ] CT adapter and parser implemented in `app/service/discovery/ct.py`.
  - [ ] Discovery paging fixture tests **COL-01** passing in `tests/discovery/test_ct.py`.
  - [ ] Type checks pass (`mypy --strict app/service/discovery/ct.py`).

---

### Story 3.3: DNS Resolver & SSRF Egress Gate
- **Coding-agent model**: `gpt-6-sol` with reasoning effort `high`.
- **Price/performance rationale**: DNS rebinding, mixed address answers, connection pinning, redirects, and cloud metadata blocking make this a critical SSRF trust boundary.
- **Escalation rule**: Do not downgrade the egress design or bypass analysis. Sol may add regression fixtures after Astra fixes the boundary.
- **Goal**: Build an isolated DNS resolver and egress screening gate rejecting all private, link-local, loopback, and cloud metadata destinations.
- **Invariants Enforced**: INV-06
- **Technical Contracts**:
  - `runner/dns.py`:
    - `resolve_and_screen(hostname: str) -> list[ipaddress.IPv4Address | ipaddress.IPv6Address]`:
      - Resolves A / AAAA records via controlled upstream resolvers.
      - Blocks forbidden IP ranges:
        - IPv4: `0.0.0.0/8`, `10.0.0.0/8`, `127.0.0.0/8`, `169.254.0.0/16` (including cloud metadata `169.254.169.254`), `172.16.0.0/12`, `192.168.0.0/16`, `224.0.0.0/4`, `240.0.0.0/4`, `255.255.255.255/32`.
        - IPv6: `::1/128`, `::/128`, `::ffff:0:0/96` (IPv4-mapped), `fc00::/7`, `fe80::/10`.
      - Rejects mixed answer sets containing any forbidden IP.
      - Implements DNS anti-rebinding: pins the validated IP address for the duration of the connection.
  - `runner/egress.py`:
    - Egress HTTP client / transport hook enforcing destination IP pinning and blocking redirects to private IP addresses.
- **Acceptance Criteria**:
  - Requests attempting to resolve `127.0.0.1`, `169.254.169.254`, `localhost`, or private RFC1918 subnets are immediately denied before any TCP handshake (**NET-01**).
  - HTTP redirects towards internal IP addresses are blocked (**NET-01**).
  - DNS rebinding attacks where host changes from public to private IP are rejected (**NET-01**, **NET-02**).
- **Definition of Done (DoD)**:
  - [ ] `runner/dns.py` and `runner/egress.py` implemented.
  - [ ] Adversarial test suite **NET-01** and **NET-02** passing in `tests/runner/test_ssrf_gate.py`.
  - [ ] Type checks pass (`mypy --strict runner/`).
