# Export format

What leaves the tool when someone exports a finished scan: a JSON file with everything, two CSV files for spreadsheets, and the printable report. All of them are built from the same stored facts (`app/service/export.py`, `app/service/report.py`); nothing is looked up again when you export, and two exports of the same scan are identical apart from the moment they were made.

## Who, when, where

Anyone who can open the assessment can export it; a stranger gets a 404, as for every page. Exports describe the **latest scan** and only once it has finished (completed, with gaps, failed or cancelled; a cancelled scan says so in the report and in the JSON). Any other scan of the assessment that has ended can be exported by adding `?scan=<id>` to the address; the scan history links to them. What the team decided about a finding belongs to the assessment, so the export of an older scan shows today's decisions. Every export writes a line to the `app.audit` log (`export: kind=… assessment=… scan=… by=…`, never the content) and is served with `Cache-Control: no-store`.

| What | Address (`/assessments/<id>/…`) | File name |
|---|---|---|
| Printable report (HTML) | `report` | opens in the browser; print or save as PDF there |
| Everything (JSON) | `export/scan.json` | `example.com_2026-10-05_scan.json` |
| Hosts (CSV) | `export/hosts.csv` | `example.com_2026-10-05_hosts.csv` |
| Findings (CSV) | `export/findings.csv` | `example.com_2026-10-05_findings.csv` |

The date is the day the scan was created. File names are ASCII whatever the domain looks like.

## JSON

`format.name` is `web-due-diligence-export`; `format.version` is `1`. The version changes only when a key is removed, renamed or changes its meaning; new keys can appear without a new version, so readers should ignore keys they do not know.

| Key | Content |
|---|---|
| `format` | `name`, `version` |
| `generated_at` | when the export was made (ISO 8601, UTC) |
| `tool` | `name`, `ruleset` (a digest of the rules that judged the scan), `rules` (rule id → version) |
| `assessment` | `id`, `domain` (ASCII), `domain_display` (as the user would read it), `label`, `created_at` |
| `scan` | `id`, `status`, `created_at`, `started_at`, `finished_at`, `options` (limits and hosts added by hand), `findings` (`state` is `ready`, `failed` or `not_evaluated`; then what the evaluation recorded: time, rule set, counts, rules that crashed, findings dropped by the cap) |
| `summary` | the three cards and the coverage band as the pages show them: `coverage`, `where`, `who`, `secure` |
| `discovery` | what discovery stored: `counts` (names seen, names outside the domain), `wildcard_patterns`, `sources` (what each one answered), `planned` (hosts reviewed and hosts left out by the limit) |
| `domain_checks` | the checks of the domain itself (email, registration, name servers, security.txt, HSTS preload, breaches), in display order |
| `hosts` | every reviewed host, by name: `id`, `hostname`, `source`, `ct_sources`, `first_seen`, `last_seen`, `open_findings`, `top_severity`, and its `checks` in display order |
| `findings` | every finding, open ones first, most serious first (see below) |
| `attributions` | the data sources this scan actually used, with what they were used for, their terms and a link: `key`, `name`, `used_for`, `terms`, `url` |

A **check** is `{id, check, status, reason_code, source, collected_at, duration_ms, data}`. `status` is one of `ok`, `no_data`, `unavailable`, `error`, `skipped` (checks that had not run when a scan was cancelled are `skipped` with the reason `scan_cancelled`); `reason_code` says why when it is not `ok`; `data` is the check's stored result, exactly as the check wrote it (see the [checks catalogue](checks-catalog.md)). A check that did not answer is exported with its status and reason, never as an empty value, and a missing finding is never to be read as "clean".

A **finding** is `{id, rule_id, rule_version, severity, confidence, attribution, scope, subject, fingerprint, host, host_id, address, title, message, advice, facts, params, evidence, status, decision}`:

- `severity` is `critical`, `high`, `medium`, `low` or `informational`; `confidence` is `high`, `medium` or `low`; `scope` is `host`, `address` or `domain`.
- `fingerprint` is stable across scans (`sha256(rule | subject)`): use it to follow a finding over time.
- `evidence` lists the check results the finding rests on (`check_id` is the `id` of a check in the same document).
- `status` is `open`, `accepted` or `false_positive`. `decision` is `null` for an open finding, otherwise `{status, reason, decided_by, decided_at, review_by, acceptance_expired}`. An acceptance whose `review_by` date has passed is `open` again, and its decision stays visible with `acceptance_expired: true`.

Codes (`rule_id`, `severity`, `status`, `check`, `reason_code`, …), numbers and dates do not depend on a language. The texts (`title`, `message`, `advice`, the labels of `facts`, the attributions' `used_for` and `terms`) are in the language of the person who exported. Cookie values and provider keys are never stored, so they cannot be in an export.

## CSV

All CSV files are UTF-8 with a byte order mark (so that Excel reads umlauts correctly), comma-separated, CRLF line ends, quoted as RFC 4180 says. A cell with several values separates them with `; `. Booleans are `true` or `false`; dates are ISO 8601; an empty cell means *no value* (not applicable, or not determined: look at `tls`, `gaps` or the JSON for why).

**Formulas.** A text that starts with `=`, `+`, `-` or `@` (or a tab or line break) gets a leading apostrophe, so that a spreadsheet shows it instead of calculating it. Numbers are written as numbers and are not touched.

### Hosts: one row per reviewed host

| Column | Content |
|---|---|
| `hostname` | the host name |
| `source` | how the name entered the scan: `ct` (Certificate Transparency), `manual` (added by hand), `apex` (the domain itself), `fallback` (`www.` tried because discovery failed) |
| `addresses` | the public addresses DNS returned |
| `countries` | country codes (ISO 3166-1) of the host's own addresses |
| `cities` | `City, CC` for each city the location database knows for them |
| `networks` | the networks or organisations the databases name for the addresses |
| `cdn_edge` | `true` if every address is a CDN or anycast edge |
| `cdn_waf` | the CDN, proxy or WAF recognised in front of the host, from its response headers, cookies, DNS alias and the network of its addresses; empty if none was recognised (which is not the same as none) or the check did not answer |
| `ports` | open ports a scanner saw on the addresses that speak for the host |
| `cves` | CVE identifiers the scanner associated with them (leads to verify, not confirmed vulnerabilities) |
| `tls` | `valid`; or why the certificate is not (`expired`, `not_yet_valid`, `hostname_mismatch`, `untrusted`, `verify_failed`, `handshake_failed`, `not_verified`); or `<status>:<reason>` when the check did not answer (`error:timeout`) |
| `tls_valid_until` | the end of the certificate's validity (`YYYY-MM-DD`) |
| `tls_days_left` | days until then; negative if it has passed |
| `http_status` | the status code of the final response |
| `http_scheme` | `https` or `http`: the scheme that answered |
| `technologies` | what the response headers and the first page show the host is built with or loads (web server, language, CMS, libraries, analytics, ...), with the version where one showed (`PHP 8.4.26`); the CDN or WAF is in `cdn_waf`. A technology that is not listed is not recognised rather than absent |
| `blocked_by` | the security DNS resolvers (Quad9, Cloudflare (1.1.1.2)) that refuse the host's name, which they do for names that their threat intelligence flags as malicious; empty if none does (which proves nothing: each knows only part of the bad names) or the check did not answer |
| `listed_on` | what the offline blocklists (Phishing.Database, Feodo Tracker, and URLhaus when it is enabled) name, one entry per thing: `host: <lists>` for the host's own name, `alias <name>: <lists>` for a name it is an alias for, `address <ip>: <lists>` for one of its own addresses (an address of a CDN or other shared edge is not held against the host and is left out); empty if nothing is listed (which proves nothing: the lists hold only what their maintainers have seen) or the check did not answer |
| `open_findings` | open findings about the host and the addresses it resolves to |
| `top_severity` | the highest severity among them |
| `gaps` | `true` if a check of this host failed, was unavailable, did not finish or was cancelled |

An **edge address is not a place**: when an address belongs to a CDN or anycast network the location database says where it is announced, not where the data is, so such addresses are left out of `countries` and `cities` (and shown in `networks` and `cdn_edge`). Ports and CVEs of shared infrastructure are left out of `ports` and `cves` for the same reason.

### Findings: one row per finding

| Column | Content |
|---|---|
| `severity` | `critical`, `high`, `medium`, `low` or `informational` |
| `status` | `open`, `accepted` or `false_positive` |
| `rule_id` | the rule that raised it ([rules.md](rules.md)) |
| `title` | the rule's title |
| `message` | what was found, for this host |
| `host` | the host it is about; empty for the domain or an address |
| `scope` | `host`, `address` or `domain` |
| `address` | the IP address, for findings about one |
| `subject` | what the finding is about, e.g. `host:www.example.com` |
| `confidence` | `high`, `medium` or `low` |
| `attribution` | how far the evidence speaks for the host (for example `hostname_supported`, `shared_infrastructure`, `domain`) |
| `advice` | what to ask or do |
| `evidence` | the checks it rests on (the first three), e.g. `tls: www.example.com` |
| `decided_by` | who accepted it or marked it as a false positive |
| `decided_at` | when |
| `decision_reason` | why (required for every decision) |
| `review_by` | the date after which an acceptance stops counting |
| `acceptance_expired` | `true` if that date has passed (the finding is then open again) |
| `fingerprint` | the stable identifier of the finding |

## The report

`report` is one HTML page, built to be printed (A4) or saved as PDF from the browser's print dialog. Its sections:

1. **Summary**: how secure (open findings by severity, the most serious rules), where the data is (countries and cities, hosts outside the allowed area, CDN edges), who processes it (networks, DNS, mail, services allowed to send mail, registrar), and the coverage.
2. **Open findings**, by severity, each with its evidence.
3. **Findings the team decided about**: accepted findings and false positives, each with the reason, who, when and the review date.
4. **Hosts**: addresses, location with cities, ports, TLS, HTTP and open findings per host.
5. **The domain itself**: email security, registration, name servers, security.txt, HSTS preload, breaches.
6. **Method and limits**: the discovery sources and what each answered, the host limit, what the checks do, the rule set, and what the report cannot say.
7. **Data sources and attributions**: the sources this scan used, with their terms (for example *CC BY 4.0: IP geolocation by DB-IP.com*, as the licence requires).

The report is a snapshot: it states what was observed at the time of the scan and when it was generated. It is not a certification, an audit or a penetration test, and it says so. The page loads no scripts except the print button, and every text that came from the network or from a person is escaped.

## What an export does not say

- A host beyond the limit (`MAX_HOSTS_PER_RUN`) is not in the file. How many were left out is the sum of `discovery.counts.dropped_by_cap` (cut while the sources were merged) and `discovery.planned.dropped_by_cap` (cut when the scan was planned); the coverage in `summary` adds them up.
- A finding that is not there is not a clean bill of health: the rules only judge what the checks collected.
- A location is where an address is announced, not where data is stored or processed; a provider named is one seen in public records, not a legal processor.
- Ports and CVEs are a scanner's snapshot and can be out of date.
