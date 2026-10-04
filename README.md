# Web Due Diligence

Technical due diligence from a single pane of glass. Enter a vendor's domain; the tool discovers its hosts from Certificate Transparency logs and reviews each one — DNS, TLS, HTTP security headers, network and location, open ports and CVEs, email security, registration data — and answers three questions: **Where is the data? Who processes it? How secure is the external posture?**

> **Status:** MVP under construction (branch `mvp`). Plan: [docs/roadmap.md](docs/roadmap.md).

**Responsible use.** Only assess domains you are allowed to assess. The tool sends standard, low-impact requests (DNS, one TLS handshake, one HTTP GET) and queries public data sources; it never logs in, scans ports or exploits anything.

## Development

Commands and conventions: [CLAUDE.md](CLAUDE.md). Documentation index: [docs/README.md](docs/README.md).

## Licence

Apache-2.0 (decided; the `LICENSE` file and third-party notices are added in roadmap story S5.1).
