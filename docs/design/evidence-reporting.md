# Evidence, reports, language and retention

Owner: artifact lifecycle, frozen technical reports and deletion. Read [data model](data-model.md), [access control](access-control.md) and [collection](collection.md). These contracts preserve useful evidence without turning the application into a TPRM replacement.

## 1. Evidence provenance

Each fact points to its typed source result; each retained source artifact records origin, provider/method, observation/retrieval time, media type, exact byte count, SHA-256, collector/parser version and rights policy. Provider-reported verification and analyst attribution are separate. A redacted derivative has a new ID/hash and an explicit derivation relationship, not an overwritten original.

Do not retain all content by default. Prefer bounded selected headers, certificate metadata, normalised results and screenshots. Strip secrets from URLs/cookies/headers before persistence unless a specifically justified evidence requirement exists. There is no user upload workflow, raw HTML preview, authenticated target collection or external AI translation.

Source rights policy distinguishes: live use, cache validity, historical normalised-result retention, raw-payload retention, inclusion of derived facts in internal reports, inclusion of raw payloads in exports and client/external distribution. User authorisation cannot override a provider restriction. Store rights policy version and the inclusion decision in each issued report; do not assume a paid subscription permits every redistribution use.

An unavailable/missing entitlement is visible in coverage. If evidence cannot lawfully be retained for the intended report period, omit restricted content with an explicit limitation, use only permitted derived information, or block that export for an authorised configuration correction. Do not silently promise a self-contained reproducible source when the source cannot be retained. Source acquisition time/rights metadata may itself have restrictions; minimise it accordingly.

## 2. Storage interface

Define one small explicit interface with these operations and semantics:

| Operation | Contract |
|---|---|
| `stage(stream, limits, expected_type)` | Stream bounded bytes to an opaque new staging reference; no arbitrary client path/key |
| `commit(stage_ref, artifact_id)` | Publish a new immutable version and return opaque locator/version/size/hash; cannot overwrite existing different bytes |
| `open(locator, version)` | Bounded streaming read by trusted service after authorisation; no public URL exposure |
| `verify(locator, version, expected_hash, expected_bytes)` | Validate byte integrity; corruption is a failed artifact, not a missing image silently dropped from reports |
| `delete(locator, version)` | Idempotent physical deletion; a hold/lock conflict is explicit and retriable/escalatable |

The service, not the storage driver, decides permissions, retention and provider rights. Drivers implement filesystem initially and S3 when selected; avoid implementing optional backends solely to satisfy a hypothetical extension.

Filesystem: private root outside static/web directories, random artifact IDs, per-service filesystem permissions, encrypted volume/backup and separate staging. Avoid check-then-open symlink races: open relative to a trusted directory handle with platform-appropriate no-follow/exclusive creation controls, or an equivalent proven safe approach. Filename/path components are generated, not assembled from hostnames or download names. Atomically rename within the same filesystem on commit; flush as required for the durability level. Application-level immutability does not protect against a root administrator.

S3: private bucket, TLS, least-privilege identities, encryption, new keys/versions and explicit lifecycle rules. Record the returned version ID where enabled. Deleting the current key alone may leave older versions; retention tests cover all versions. Do not use public ACLs or long-lived signed URLs as the baseline. Evaluate object-lock policy carefully because it can prevent configured deletion.

Safe download names are generated from report ID/version/locale, not uncontrolled provider strings. Return known Content-Type, `X-Content-Type-Options: nosniff`, private/no-store cache policy and safe attachment disposition where applicable. Inline screenshots must be validated image outputs, never arbitrary SVG/HTML. Prefer streaming under app authorisation to preserve revocation and audit checks.

## 3. Staging and consistency

Artifacts and DB rows cannot commit atomically across systems. Stage bytes, compute size/hash, validate type, then commit the storage object; commit its DB metadata and result relationship in a short transaction. A content write without a DB commit becomes an orphan eligible for later cleanup, never automatically public. Metadata still in `staged` is not readable to ordinary users.

Use a staging generation/reference bound to the job lease. A stale worker's artifact cannot be attached to a new logical result. Retry with the same artifact logical key accepts identical content or returns a conflict; it never replaces accepted bytes. Reconcile committed metadata with missing storage into `corrupt`/unavailable state and alert IT Security. Keep orphan cleanup outside active lease windows; it must not delete a live worker's upload.

## 4. Frozen report contract

One Phase 1 report version is based on one terminal scan (`complete/partial/failed/cancelled`) and selected technical annotations. Normally require at least useful results; a failed/cancelled run can produce a limitations-only report only when the owner deliberately selects that option. Do not add arbitrary multi-run comparisons in the first release.

Snapshot schema version 1 contains:

- Report identity, version, workspace/case display labels intentionally included, preparer and source run ID/window.
- Canonical scope, collection profile, excluded names/counts, rule/adapter/config versions and vantage information.
- Infrastructure/provider/security summaries as structured facts and message keys/parameters.
- Host/endpoint inventory, technical findings, confidence, attribution and source timestamps.
- Planned/applicable/succeeded/failed/skipped counts, partial/cancelled reasons and provider/licensing limitations.
- Selected analyst revisions as of a recorded cutoff; no live note joins.
- Evidence inclusion list with report-owned artifact IDs, integrity/provenance metadata and source-rights decisions.
- Report retention/policy, requested locales and review policy/hash.

Store and hash canonical UTF-8 JSON with deterministic key ordering, explicit schema version, UTC ISO timestamps, stable array ordering and no NaN/Infinity. Keep collection measurements as typed numeric/string values, not locale-formatted numbers. Include the canonicalisation algorithm/version; hashing arbitrary ORM serialisation is not a stable evidence format.

Source result IDs are lineage references; report reading does not depend on access to or continued existence of source rows. Copy permitted evidence into report-owned artifacts before issuance. Physical deduplication across independent scopes is deferred; it complicates expiry and authorisation. A report-only viewer reads frozen content and these copies only.

## 5. Preparation, approval and publication

1. Authorise preparation and require a terminal run. In a short consistent transaction select facts/annotation revisions, calculate rights decisions and retention, allocate version, freeze snapshot data and enqueue preparation. Concurrent note edits after the cutoff do not enter that snapshot.
2. A preparation worker materialises report-owned evidence copies, verifies all required bytes and freezes the final evidence index/snapshot hash. If a source expires/disappears before copying, fail preparation visibly; do not publish a misleading complete report. Coordinate retention through bounded preparation leases, not an unlimited implicit hold.
3. Move to `draft`. Reviewer preview uses the frozen data. Changing selected content creates a replacement draft version or rebuilds a still-unapproved draft with a new revision/hash; it always invalidates approvals/renderings prepared against older content.
4. If four-eyes is enabled, require eligible independent approval tied to the exact snapshot/policy hash. With review disabled, the owner may proceed directly. Record which policy was applied.
5. On issue request, recheck active permissions, freshness, rights, snapshot hash and required approval. Freeze the planned issuance metadata and issue time; derive the report expiry once. The background job renders requested locales offline into unpublished artifacts. A failed attempt may reuse the frozen job inputs; a materially new issue attempt must deliberately regenerate issuance metadata and dependent outputs.
6. Verify PDF/evidence hashes, page/output validity and manifest content. In a short transaction recheck issue authority/policy and publish the version plus completed requested language artifacts together. If a required rendering fails, do not mark that language or the initial issue set as issued.
7. After issuance, amendments create another version. A previously unissued locale may be added from the exact existing snapshot, issue metadata and pinned catalog/template version without extending expiry; if those resources are unavailable, create a new explicit report version instead of pretending equivalence.

Render content cannot change after approval. Publishing with changed required review/rights policy requires re-evaluation and, where needed, new approval; do not use an old background task to bypass a policy change. Losing the initiator's permission before publication stops issuance and preserves the draft for an authorised owner.

## 6. Rendering and integrity manifest

The report renderer receives staged safe data/assets, not credentials or general DB access. It uses application-owned Jinja templates, local bundled fonts/styles and offline browser/PDF rendering with all network access denied. No user-supplied template, raw collected HTML, external image URL, script or CSS URL is allowed. Escape source strings; place screenshots as validated images. Resource and page-count ceilings apply to pathological content too.

Manifest records the snapshot hash, artifact IDs/hashes/bytes/media types, rendering/template/catalog versions, locale, report identity, issuance time and provenance limitations. The PDF may show the snapshot hash. Its own final file hash belongs in the external manifest; do not attempt to embed a self-referential whole-PDF hash. The manifest can be detached-signed later using a protected key if required. Hashes alone detect differences against trusted reference data; they are not independent proof of origin or trusted time.

Optional evidence bundles contain only approved report-owned contents and safe generated archive paths, with a manifest. Never export the database, a whole storage prefix or unrestricted provider raw feeds. A revoked or expired user cannot create/download a bundle from an old job ID. If asynchronous export is introduced, recheck access on completion and download.

## 7. DE/EN and UI translation

Report locales: `en` and `de-CH`. Separate UI preference from output locale. Store finding IDs, severity, status and facts in language-neutral form; message keys resolve through versioned catalogs. Use Swiss Standard German, correct umlauts and `ss`; do not mechanically replace characters in raw evidence.

Translate all application-owned report titles, findings, status/limitation text, table headers, captions and validation errors. Both variants have identical technical facts, evidence IDs and severity. Format dates/numbers for the chosen locale while retaining explicit timezone and UTC provenance. Long German text must be tested for wrapping, pagination and missing glyphs.

Source banners, provider descriptions, screenshots and analyst notes remain verbatim in their original language. Provide translated application summaries from structured facts; label source excerpts as original. Do not fabricate translations of arbitrary technical evidence or send it to external services automatically. Missing required report translations block issuance in that locale with a clear error; UI translation may fall back to English while the optional full UI catalog is completed.

## 8. TPRM handoff

The report and evidence package should remain intelligible without this application: inline essential figures, stable evidence IDs, source times and scope limitations. Phase 1 offers download and manual human confirmation of upload to TPRM; no connector is implied. Record exact version/locale/hash plus human actor/time/reference. A correction appends a handoff event rather than rewriting history. Treat a pasted TPRM URL as text/safe external navigation, never as an automatic server fetch.

TPRM owns its stored final copy and supplier decisions. This platform's local purge cannot delete that copy and must not silently extend retention because handoff is unconfirmed. Show upcoming expiry and unconfirmed handoff on the report list; IT Security decides whether to transfer or use an explicit authorised hold. Provider report-transfer rights must cover the intended TPRM destination.

## 9. Retention implementation

Default 12 calendar months, with separately configurable classes. Add calendar months to the anchor in UTC, preserving time and clamping the day to the last valid day of the target month; for example, 2028-02-29 plus 12 months becomes 2029-02-28. Do not approximate as 365 days. Defaults apply prospectively; store policy version, anchor and computed deadline per retained aggregate.

| Class | Proposed anchor/lifecycle |
|---|---|
| Runs/results/source artifacts | Terminal run time + configured months; collecting work has a maximum run age and staging TTL |
| Standalone technical annotations | Creation time + configured months; frozen included annotations are also part of report snapshot |
| Issued report, renderings and copied evidence | Frozen issuance time + configured months; every locale shares the same deadline |
| Draft reports | Creation time + configured months, with shorter staging TTL; never immortal because unissued |
| Audit | Event time + separately configurable period, default 12 months |
| Staging/orphans | Proposed 24 hours after last activity, outside active bounded leases |
| Accounts/memberships/configuration | Operational lifecycle, not deleted by a scan's age |
| Minimal assessment/host indexes | Prune when no retained results/reports/notes or active work require them; do not retain stale supplier metadata indefinitely |

Provider archival deadlines may be shorter. Avoid making an otherwise retained report depend on a raw source that must expire early: include permitted derivatives/limitations at preparation time. Where report content itself has a shorter permitted lifetime, enforce that effective deadline or exclude it before issuance. Legal/administrative holds must have scope, reason, authorised actor and review date; a hold does not create ordinary viewing rights or silently extend a provider licence.

At `expires_at`, normal read/export predicates deny access immediately. A scheduled cleanup selects expired, unheld aggregates in bounded batches, marks `deletion_pending`, cancels dependent jobs and removes live payload references. Delete storage artifacts idempotently, including old object versions and derivatives, then finalise DB purge/minimal deletion records. Retry storage failure and alert on overdue purge; never label an inaccessible but still physically present object as deleted.

Frozen report copies survive source deletion until their own deadline. Delete parent case metadata only when all retained descendants/holds are accounted for. Retention jobs use narrow authority, dry-run counts and audit; they do not take arbitrary file paths supplied by users. Bulk retroactive expiry changes require an impact preview and explicit review under project change rules.

Backups use a separately configured finite expiry. Deletion records required for safe restoration must survive the oldest restorable backup, even if ordinary audit retention is shorter; retain minimal opaque identifiers, not evidence content. On restore, reapply expired/deleted records and holds before opening access, then reconcile artifact versions and job leases. Document residual backup retention beyond live deletion. Downloaded files and TPRM copies have independent retention outside this system.
