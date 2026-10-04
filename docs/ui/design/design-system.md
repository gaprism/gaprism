# Design system implementation

Approved 2026-10-02. This is a reusable Flask/Jinja/Tailwind presentation baseline with a runnable **synthetic, local-only preview**. It is not the application's authentication or persistence milestone. Read the [approved plan](../superpowers/specs/2026-10-02-tailwind-design-system-design.md) for rationale and the [verification record](design-system-validation.md) for tested limits.

## Run and build

From the repository root in PowerShell, after installing dependencies from the existing locks:

```powershell
uv sync --frozen
npm ci
npm run build
.\.venv\Scripts\python.exe scripts\build-translations.py
.\.venv\Scripts\python.exe -m flask --app app.preview:create_preview_app run --host 127.0.0.1 --port 5055
```

`uv sync --frozen` and `npm ci` are the clean-machine installation path. This implementation reused the already installed locked dependencies; the tested operations were build, catalog compilation, runtime and validation, not a fresh reinstall. No provider credentials, PostgreSQL, Docker or `.env` are needed for this preview. Restart the server after recompiling translations, because gettext caches catalogs.

Open `http://127.0.0.1:5055/preview/de-CH/overview`. English is available at `/preview/en/overview`. Other pages: `cases`, `components`, `infrastructure`, `providers`, `security`, `evidence`, `reports`, `sharing`, `new`, `access`. `components` links to error, denied, expired, loading, stale and empty-result examples. Every screen identifies the synthetic context; nonimplemented data-changing actions are disabled.

The preview has no login and therefore rejects non-loopback remote addresses and untrusted Host headers. It does not trust forwarded client addresses. **Do not reverse-proxy, tunnel, expose or mount this factory in production:** a local reverse proxy can itself appear as loopback. This restriction is a development boundary, not authentication. Only invented fixtures belong here.

## Ownership and boundaries

| Source | Responsibility |
|---|---|
| `assets/tokens.css` | Semantic palette, type families and radii; CSS-first Tailwind `@theme` |
| `assets/app.css` | Source scanning, common utilities/components, density, focus, responsive rules |
| `assets/report.css` | Independent offline A4 print composition, repeated page identifiers, local fonts |
| `app/templates/components/ui.html` | Reviewed icon paths, actions, fields, badges, notices and empty states |
| `app/templates/base.html` | Landmarks, responsive navigation, language links and local assets |
| `app/templates/assessments/` | Compact overview, filtered host results, inspector, gallery and evidence views |
| `app/templates/reports/` | Version presentation and separate recipient/print document |
| `app/templates/sharing/` | Private case and exact-version sharing presentation |
| `app/blueprints/preview.py` | HTTP validation and full/partial rendering; read-only GET routes |
| `app/service/preview.py` | Frozen synthetic view models, filter/sort and minimal report projection |
| `app/preview.py` | Explicit preview factory, locale selection and security headers |
| `app/translations/de_CH/LC_MESSAGES/messages.po` | Swiss German gettext catalog; English msgids are the source locale |
| `scripts/copy-assets.mjs` | Copy locked HTMX, print CSS and licence notices into local static assets |
| `scripts/build-translations.py` | Validate/compile gettext catalog; generated `.mo` is ignored by Git |
| `scripts/verify-preview.mjs` | Dependency-free Chromium protocol checks with the installed browser |

Never edit built `app/static/css/app.css`, `report.css` or copied `htmx.min.js` directly. Rebuild from source. No runtime CDN, webfont service, external favicon or third-party JavaScript is used. Node is a build/test tool, not the application runtime. Original SVG icons and the clearly labelled synthetic screenshot are repository-owned; licence/provenance for vendored assets is in [third-party notices](../third-party-notices.md).

## Token and density contract

| Role | Value / rule |
|---|---|
| Canvas / panel / subtle | `#F8FAFC` / `#FFFFFF` / `#F1F5F9` |
| Primary / secondary text | `#0F172A` / `#475569` |
| Decorative / control border | `#E2E8F0` / `#64748B`; decorative borders do not identify controls |
| Action / hover / on-action | `#0F766E` / `#115E59` / white |
| Focus | `#1D4ED8`, 2 px outline and 2 px offset |
| Selection | `#EFF6FF` background and `#1E40AF` text |
| Critical / high / medium / low | Dedicated dark text on light background; see source tokens |
| Body / table / metadata | 16 px / 14 px / 12 px; metadata is not the only source of essential facts |
| Controls | At least 40 px; at least 44 px for coarse pointers |
| Spacing / radii | 4 px base scale; 4/6/8 px radii |
| Sidebar / inspector | 208 px from 1024 px; 368 px inspector from 1536 px |
| Motion | Short colour transitions; disabled under reduced motion |

Colour always accompanies text. A valid certificate uses neutral blue, never a global green "secure" claim. Action confirmation and technical verdicts must remain separate. The design has one density and light theme; dark mode, column resizing and personal density settings are deferred.

The small-screen navigation uses native `details`; tablet navigation remains inline. Wide tables scroll inside labelled keyboard-focusable regions. Long hostnames wrap, retain the full identifier and use `bdi`. The current fixtures are ASCII hostnames; production normalisation must detect and label unusual Unicode/bidirectional control characters without silently rewriting source evidence.

## Component contracts

Import macros `with context` so locale/status labels are available. Use application-owned arguments only; never pass provider-defined attributes, URLs, styles or event handlers.

| Macro | Contract |
|---|---|
| `action(label, href=None, variant='secondary', disabled=False, type='button')` | Internal trusted URL creates a link; otherwise a native button. Variants are `primary`, `secondary`, `quiet`, `destructive`. Button type is allowlisted. No real mutation may be implemented as a GET link. |
| `badge(value, dimension='execution')` | Separate execution, technical, severity, access and attribution dimensions. Literal allowlisted colour classes; unknown values display the neutral unknown label. |
| `field(id, label, help='', value='', error='', type='text', autocomplete='off', disabled=False)` | Stable unique ID, explicit label, connected help/error and `aria-invalid`; Jinja escapes the value. `type` and autocomplete are developer-owned constants. |
| `notice(title, body, danger=False)` | Persistent explanation with icon and text; use an outer live region only for a newly actionable update. |
| `empty(title, detail)` | Empty, denied, expired, failed and loading states must explain their specific meaning; do not use one universal "nothing found" state. |
| `icon(name)` | Original, reviewed SVG paths; decorative SVG is hidden from assistive technology. |

Native dialogs are enhanced with `showModal`; Escape closes, cancellation has initial focus, and focus returns to the trigger. No destructive demonstration changes any data. Without JavaScript, core navigation/filtering/report reading still works; the dialog and browser-print buttons are enhancements.

The table, report document and evidence layouts remain focused partials instead of highly parameterised universal macros. This intentionally favours readability over a generic component framework. For a future reuse, extract only the duplicated presentation contract; keep scope decisions in services.

## Evidence semantics

Execution (`partial`, `failed`, etc.) never substitutes for a technical result (`no_match`, `unknown`, `not_checked`). Severity never substitutes for confidence or attribution. Provider quota errors are coverage gaps, not security findings. Endpoint geography is not proof of storage/backup residency; observed infrastructure is not proof of contractual processing.

The fixture set includes a shared IPv4 address, IPv6, a long hostname, invalid TLS, failed DNS, a missing screenshot and exhausted reputation quota. Deeper-check imagery is absent for ineligible hosts. Report-only rendering receives a narrow frozen projection, not a case model, and has no case/raw-artifact/future-version links. In this preview that is a rendering property, **not an implemented access-control system**.

Production host aggregation still needs service-supplied per-endpoint results, including mixed TLS outcomes, real evidence identifiers, source versions and observed/retrieved times. Do not infer those facts from the preview's simplified single-address rows or use its fixed summary counts for real cases.

## HTMX and failure handling

Filters are GET forms with URL-backed query, coverage and hostname sort. The server validates enum values and limits search length. Full page navigation is the fallback. HTMX replaces the results section with `outerHTML`, preserving the filter form and its focus; `hx-sync="this:replace"` cancels superseded requests. Details have their own synchronisation boundary. Below inspector width a host link navigates to its canonical full page.

Pending work uses `aria-busy` and a status label. Failed refreshes retain previous rows and show a persistent stale-results warning. Closing an inspector restores the triggering link, or the search field if filtering removed the link. There is no scheduler/polling in this read-only preview. Future real polling must use the same focus/stale-response policy and stop at terminal states; do not add a guessed percentage from hostname discovery counts.

HTMX inline styles/eval/script injection and history snapshots are disabled. CSP allows scripts/styles/fonts/images/connections only from self; frames, objects, inline execution and external connections are blocked. Templates autoescape collected-looking text. No raw remote HTML is embedded, and no target page is actually loaded.

## Translation and print

Use Flask-Babel `_()` for application-owned strings. Add English msgids and Swiss German translations together. Dynamic status labels must also exist in the catalog. Preserve source evidence language; no remote translation service is configured. UI locale is in the preview route. Report version links independently choose DE or EN, and both languages render the same snapshot facts. Raw timestamp examples are UTC; production formatting must keep timezone explicit.

The report template deliberately does not extend the workspace layout. Its reduced annex has four columns, repeated table headers, wrapping hostnames and textual outcomes. Print styles use A4, 11 pt body, 9 pt appendix and local Inter 4.1 regular/semibold fonts. Page margins repeat the report identity and page counter. Browser "Print / save PDF" is usable in the preview; this is **not** the future immutable server-side report renderer, signature/hash manifest or licensed evidence export.

## Production integration checklist

1. Implement the architecture's authentication and resource-scoped authorisation first. Do not rename the preview factory into production or treat its synthetic state query parameters as permissions.
2. Replace fixtures with permission-filtered view models from `app/service/`; keep ORM objects, live provider payloads and role interpretation out of templates. Never load inaccessible data and merely hide its HTML.
3. Implement CSRF, idempotency and audit trails when adding real POST actions. No preview action currently requires a secret or sends credentials.
4. Apply authorisation/expiry to every full view, HTMX partial, artifact and exact report version. Test report-only recipients against guessed case IDs and future versions.
5. Render issued reports from immutable authorised snapshots with licence-aware artifact inclusion and a pinned offline renderer. Downloading alone must not mark TPRM transfer complete.
6. Add real pagination/caps only with backend query contracts and measured volume. Six synthetic rows do not establish capacity.
7. Preserve the separate collection/egress trust boundary; never put target collection inside web routes or the preview browser.

## Engineering and security assessment

KISS/YAGNI: no SPA, UI kit, state store, theme switch or new runtime service. SOLID/DRY: narrow macros, thin route adapter and frozen presentation models; domain decisions will remain in services. Least privilege/fail-safe: local-only synthetic factory, disabled mutations, no secrets/providers/database, explicit unknown/failure states. Privacy/evidence: reserved fixtures, no tracking, no-store responses, restricted report projection and reproducible local assets.

The deliberate shortcut is a read-only fixture service with fixed summaries rather than production domain logic. It must not evolve into a second business layer. Full authentication, audit events, durable reports, retention enforcement, backups, abuse limits and collector isolation are unimplemented dependencies, not controls proven by this preview. This is appropriate to the approved design-system scope and noncritical development use; deploying it as the platform would violate the architecture.

See [validation](design-system-validation.md) for commands, test coverage and remaining manual accessibility work. Official implementation references: [Tailwind CLI](https://tailwindcss.com/docs/installation/tailwind-cli), [Tailwind theme variables](https://tailwindcss.com/docs/theme), [HTMX documentation](https://htmx.org/docs/).
