# Tailwind design system: design and implementation plan

Date: 2026-10-02. Status: **PROPOSED — AWAITING EXPLICIT USER APPROVAL**.
Deliverable: Markdown plan only. This document does not authorise implementation, dependency installation, asset generation, deployment or continuation of the earlier application scaffold.

## 1. Brief and acceptance boundary

Create a reusable design system for the internal SaaS technical-verification platform described in [the architecture](../../architecture.md). It must make many hosts, incomplete checks, provider observations and evidence easy to inspect, while keeping report creation and sharing understandable.

**Confirmed visual preference:** a compact analyst interface with higher information density. This replaces the initially suggested spacious presentation. Retain the confirmed Flask/Jinja/HTMX/Tailwind stack, private team access, technical-only methodology, DE/EN reports, optional full UI translation and manual TPRM handoff.

Success means an analyst can start a scoped assessment, identify coverage gaps, filter hosts, understand a finding's attribution and inspect its evidence without losing their place. A report-only recipient must receive a clear, narrower experience. Compactness must come from layout and prioritisation, not tiny text, unlabeled icons or inaccessible controls.

The plan specifies visual foundations, component contracts, page composition, interaction/accessibility rules, prospective files, implementation order and verification. It does not introduce questionnaires, supplier risk scores, new scanning capabilities, external customer accounts or a TPRM connector.

## 2. Existing state and approach

Repository inspection found architecture/rules documentation, Python/npm manifests, lockfiles and dependency directories from the interrupted setup. There is no application UI, base template, component library or CSS source to preserve yet. The current npm lock resolves Tailwind/CLI 4.3.3 and HTMX 2.0.11; these are observed versions, not an instruction to upgrade or reinstall them.

| Approach | Benefits | Costs and limits | Decision |
|---|---|---|---|
| **Project-owned semantic tokens and Jinja macros over Tailwind v4** | Fits server rendering, narrow dependency footprint, direct control over dense tables and evidence semantics | Requires explicit component/state documentation and accessibility tests | Recommended |
| Adapt a third-party Tailwind component kit | Faster generic controls and consistent primitives | Additional licence/update review; generic dashboard patterns may not fit evidence and permission states; interactive widgets can require more JS | Reconsider only for a demonstrated component gap |
| React-based component ecosystem | Broad interactive component choice | Changes the agreed rendering model and adds another state/runtime boundary | Outside the current scope |

Apply the `tailwind-design-system` skill's token hierarchy, variants, responsive patterns and accessibility guidance. Adapt its React/CVA examples into **Jinja macros with explicit variant contracts**; do not import React, Radix, CVA or a SPA runtime because a skill example uses them.

Design choice DS-01: compact, light, neutral surfaces with one teal action accent. Dark mode and a density switch are deferred; establish and validate one coherent theme first. Dark-themed screenshots remain original evidence, not recoloured UI.

## 3. Visual direction

The application should resemble a technical review workspace: clear column structure, quiet surfaces, strong typography hierarchy and persistent assessment context. Avoid large decorative hero sections, gradients, glass effects, oversized metrics and animation-driven navigation.

| Element | Proposed baseline |
|---|---|
| Main navigation | 208 px desktop sidebar; product name, Assessments, role-permitted Administration; account/language controls at the foot |
| Top context bar | Approximately 52 px minimum height; breadcrumb, current assessment/domain, relevant run/time and primary action |
| Main workspace | 16–24 px outer padding, fluid width; narrative text constrained to roughly 70 characters per line |
| Assessment sections | Overview, Infrastructure, Providers, Security, Evidence, Reports, Sharing; ordinary navigation links with active-page semantics |
| Tables | Compact default; minimum 36 px data rows, 14 px text, explicit header and alignment; rows grow when content wraps |
| Forms | 16 px input text, minimum 40 px desktop controls; minimum 44 px controls for coarse pointers where practical |
| Summary blocks | Three concise, aligned technical summaries with evidence limitations, not oversized KPI cards |
| Detail area | Full host-detail page always available; optional 352–400 px right inspector when the workspace has enough width |
| Decoration | Thin separators, modest 6–8 px corner radius, shadow only where elevation communicates overlay/selection |

Do not use a fixed-height row to clip German labels or long domains. Keep critical facts in the table; move verbose headers, certificate chains and raw provider details to the inspector/detail page.

## 4. Token system

### 4.1 Layers and naming

Use a small hierarchy: reference palette → semantic role → component use. Semantic roles are the public design API. Components select a variant by an allowlisted meaning; providers and database content never supply CSS classes.

Tailwind v4 uses CSS-first `@theme` tokens. Define utility-generating tokens in the appropriate namespaces and plain CSS variables for values not intended to generate utilities. This replaces a v3-style JavaScript theme configuration. [Tailwind theme variables](https://tailwindcss.com/docs/theme).

Proposed role prefixes: `surface`, `content`, `border`, `action`, `focus`, `feedback`, `risk` and `selection`. Keep feedback and security severity separate. Introduce a component-specific token only where a reusable component has a distinct need.

### 4.2 Reference palette

Values are sRGB reference swatches for approval, not generated CSS. Hex values are valid inputs for the proposed v4 theme; conversion to another colour space is unnecessary for the initial single theme.

| Semantic token | Proposed value | Intended use |
|---|---|---|
| `surface-canvas` | `#F8FAFC` | Application background |
| `surface-panel` | `#FFFFFF` | Tables, forms and evidence panels |
| `surface-subtle` | `#F1F5F9` | Secondary rows, toolbars and grouped metadata |
| `content-primary` | `#0F172A` | Body text and headings |
| `content-secondary` | `#475569` | Metadata and helper text; still readable |
| `border-subtle` | `#E2E8F0` | Decorative separators only |
| `border-control` | `#64748B` | Control boundaries where needed for identification |
| `action-primary` / `action-on-primary` | `#0F766E` / `#FFFFFF` | Primary actions |
| `action-primary-hover` | `#115E59` | Hover/active accent |
| `focus-ring` | `#1D4ED8` | Visible keyboard focus, with contrasting offset |
| `selection-background` / `selection-text` | `#EFF6FF` / `#1E40AF` | Selected item/navigation; include a non-colour marker |
| `feedback-danger` | `#B91C1C` | Failed action/destructive action; accompanied by explicit text |
| `feedback-success` | `#166534` | Successful action acknowledgement, never an overall supplier verdict |

| Severity | Foreground / background | Display contract |
|---|---|---|
| Critical | `#991B1B` / `#FEF2F2` | Severity label and distinct icon |
| High | `#9A3412` / `#FFF7ED` | Severity label and distinct icon |
| Medium | `#854D0E` / `#FEFCE8` | Severity label and distinct icon |
| Low | `#1E40AF` / `#EFF6FF` | Severity label |
| Informational | `#475569` / `#F1F5F9` | Informational label |

Calculated sample contrast ratios for these solid-colour pairs: body/white 17.85:1, secondary/white 7.58:1, white/primary action 5.47:1, severity pairs 6.62:1–8.01:1, control-border/white 4.76:1. These are palette calculations only. They do not establish rendered-state or application accessibility; implementation must test hover, focus, overlays, backgrounds and disabled states. Subtle separators must not be the only visible boundary of an input.

### 4.3 Typography, spacing and motion

| Group | Token proposal and rule |
|---|---|
| UI fonts | System sans stack; system monospace for domains, IPs, ports, hashes and certificate identifiers; no remote font requests |
| Text sizes | 12 px metadata only; 14 px tables/compact labels; 16 px body/forms; 18 px section titles; 24 px page titles |
| Line heights | At least 20 px for 14 px table text; 24 px for body; titles approximately 1.25–1.35 |
| Weights | 400 normal, 500 labels, 600 headings/emphasis; avoid bolding every datum |
| Numeric layout | Tabular numerals for counts/ports/time columns; end-align comparable numbers |
| Spacing | 4 px base unit; 4/8/12/16/24/32 px rhythm; use smaller gaps inside metadata groups and larger gaps between tasks |
| Radius | 4 px compact badges, 6 px controls, 8 px panels; pills only where useful for chips/status |
| Focus | 2 px visible outline/ring plus 2 px offset; never remove focus without a visible replacement |
| Motion | 100–160 ms colour/opacity changes; respect reduced motion; no shimmer or animated row reordering |
| Layers | Normal content, sticky header, popover, modal; a documented small z-index scale rather than scattered arbitrary values |

PDF typography is separate: use a bundled, licensed DE/EN font with a fixed version for stable rendering; plan for 10.5–11 pt body and at least 9 pt appendix tables. Verify the actual font/rendering pipeline after approval rather than assuming the host OS font matches another machine.

## 5. Domain status semantics

Design choice DS-02: **execution status, technical verdict, severity, confidence and attribution use separate labels and components**. A completed scan can contain high-severity findings; a provider lookup can succeed with no match; neither means the supplier is safe.

| Dimension | Example labels | Treatment |
|---|---|---|
| Execution | Queued, Running, Waiting for provider, Complete, Partial, Failed, Cancelled | Neutral/blue progress, amber limitation, red execution failure; text always names the state |
| Technical verdict | TLS valid, TLS invalid, No match for queried URL, Unknown, Not checked | Scoped to the named check; avoid a generic green “secure” badge |
| Severity | Informational, Low, Medium, High, Critical | Severity palette only; no severity for mere quota exhaustion |
| Confidence | High, Medium, Low, Unknown | Neutral label under a “Confidence” heading; never inferred from severity colour |
| Attribution | Hostname supported, IP only, Shared infrastructure, Unknown | Explicit qualifier beside the finding, not hidden in a tooltip |
| Freshness | Observed at / retrieved at; stale notice where applicable | Preserve both timestamps; human date plus timezone and expandable exact value |
| Access | Private, Shared with team members, Report-only access, Read-only | Clearly scoped text; visible action state is derived from server permissions |

“Unknown”, “not licensed”, “not applicable” and “collection failed” each have distinct explanatory copy. Blank table cells render an accessible “Not available” label where the difference matters. A failed screenshot is an evidence state, not a broken image icon. Quota exhaustion belongs to coverage, not supplier severity.

## 6. Component catalogue and contracts

Components are Jinja macros for reusable primitives, partials for server-refreshable regions, and page templates for composition. All visible labels come from the application's translation mechanism. The server prepares presentation values; components do not query databases, infer permissions or assign security severity.

| Component | Required inputs / variants | State and interaction requirements |
|---|---|---|
| Button / action link | Label, variant, size, button type or authorised URL; `primary/secondary/quiet/destructive` | Separate links from buttons; explicit pending state, visible focus; no arbitrary HTML/class injection |
| Form field | Stable ID, label, value, description, validation errors, required/disabled | Real label, linked errors/help, preserved input after validation; no placeholder-only labels |
| Select / checkbox | Label, options, selected state | Prefer native controls; no custom combobox unless needed and tested |
| Status badge | Dimension, allowlisted state, translated label, optional icon | Text plus colour; display unknown/unmapped states safely |
| Inline notice | Tone, title, explanation, optional authorised recovery action | Persistent when it affects evidence or workflow; reserve toast-like messages for secondary acknowledgements |
| Technical summary | Topic, structured conclusion, facts, coverage limitation, drill-down link | Compact and readable; no security grade or unsupported location assertion |
| Filter bar | Query, allowlisted filters, selected values, result count | Apply/reset, active filters, URL-backed state; counts contain only accessible objects |
| Data table | Caption, columns, row view models, sort, page/cursor | Semantic table/headers; sort buttons announce direction; no whole-row clickable trap around inner links |
| Host row | Hostname, endpoint summary, TLS/reputation/finding/coverage state, observation time | Identifiers inspectable/copyable; explicit detail link; truncation never the only access to a value |
| Finding summary | Rule/title, severity, confidence, attribution, source time | Independent status dimensions; evidence link and original provider qualification |
| Evidence tile | Type, permitted thumbnail/metadata, capture state, timestamp | Only authorised same-origin/staged assets; screenshot dimensions reserved; failure/expiry visible |
| Evidence inspector | Selected subject, metadata, permitted evidence, close/full-page link | Selection survives ordinary refresh; keyboard exit/return; no credentials or source HTML execution |
| Progress panel | Phase, discovered/planned/completed counts, limitations, cancellation state | No invented percentage during discovery; announce phase changes, not every polling update |
| Report version row | Version, state, locales, issued/expiry time, permitted actions, handoff state | Distinguish draft/issued, downloaded/transfer confirmed, locale unavailable/rendering failed |
| Share panel | Scope type, current effective grants, permitted actions | Assessment vs exact report version prominent; show independent access paths and download permission |
| Confirm dialog | Action, affected scope, impact, cancel/confirm | Only for consequential actions such as revoke access/cancel run; labelled focus containment, Escape/cancel and focus restoration |
| Empty/error state | Reason, safe explanation, optional permitted action | Distinguish first use, no filter matches, unavailable provider, access expiry and genuine missing results |

Macro contracts should accept constrained `variant/size/state` values. Unknown values fail validation in development or fall back safely with a controlled diagnostic; never become a partially constructed Tailwind class. A small icon macro selects only bundled reviewed SVG symbols. Decorative icons are hidden from assistive technology; icon-only controls have names and adequate targets.

## 7. Page and workflow composition

### 7.1 Assessments and creation

Landing view is a compact accessible assessment table: supplier/domain, last run, coverage state, finding summary, owner and report state. Show one “New assessment” action where permitted. Avoid a dashboard of global counts that reveals inaccessible cases.

Creation starts with domain and supplier label; show the confirmed scope and technical collection description before submission. Keep optional settings collapsed with a descriptive heading. No questionnaire or supplier-response steps. On success move to the assessment with a persistent run-progress region.

### 7.2 Assessment overview

Use the following text layout as a planning wireframe; no UI artifact is created by this plan:

```text
Assessment / example.com                 Run status     Relevant action
Overview  Infrastructure  Providers  Security  Evidence  Reports  Sharing

Observed locations       Observed providers       Security observations
Facts + limitations      Facts + attribution      Findings + coverage

Coverage / provider limitations / observation window

Priority findings                               Recent run information
Severity | finding | confidence | evidence       Counts and timestamps
```

Keep “actual data storage not technically verified” close to the observed location summary. Providers are observed dependencies, not contractual processors. Technical limitations remain visible in normal reading order, not hidden in a footer disclaimer.

### 7.3 Infrastructure and host inspection

Core table columns: hostname, IP/provider/country summary, TLS, reputation, highest finding severity with count, coverage and last observed. Keep source timestamps and confidence in the drill-down where needed. Group endpoint differences explicitly rather than implying one host has one IP or one TLS outcome.

At wide desktop widths, selecting an explicit inspect action opens the right inspector while keeping filters and selected row. On smaller widths, navigate to the full detail route and provide a return link preserving filters/page. The full route is canonical and works without JavaScript; the inspector is progressive enhancement, not a separate data source.

Show screenshots in the evidence/detail area by default. Do not insert many large thumbnails into every table row merely because screenshots exist. Use contained previews; no live iframe, remote favicon or automatic target navigation.

### 7.4 Providers and security

Providers use a compact grouped table with category, observed entity, related hosts and evidence method. Security uses a filterable findings table ordered by explicit severity and then stable tie-breakers, with confidence/attribution visible. Avoid graphs or maps without a concrete analytical question; neither is required for the first design-system implementation.

### 7.5 Reports, sharing and report-only access

Report preparation selects a terminal run, output locale(s) and permitted annotations. Show partial coverage before issuance. Support the architecture's optional four-eyes policy without inventing a mandatory approval step.

Report-only recipients get a report-specific layout with title, fixed version, locale, issue/expiry information and permitted preview/download. They do not receive case navigation, raw evidence links or controls for newer versions. “Downloaded” and “Transfer to TPRM confirmed” are different states; confirmation is an explicit human action.

Sharing starts by stating its scope: entire assessment or one report version. Effective access sources and download capability are visible. Revocation explains whether another case/report grant still provides access. Treat access control as a server responsibility; hiding a button is not a permission check.

### 7.6 Authentication and administration

Use the same typography, form/error patterns and focus rules for invitation acceptance, login, MFA and recovery. Keep those screens restrained and readable. Support password managers and paste; avoid custom multi-box MFA input unless its accessibility is demonstrated. Administration exposes only role-permitted operational settings, not a global backdoor to assessment content.

## 8. Responsive behaviour and density

| Available width | Planned behaviour |
|---|---|
| Below 640 px | One-column context/forms; collapsed navigation; clear table scroll region or prioritised stacked host summary with full detail link |
| 640–1023 px | Compact top navigation and one work area; filters wrap; details use full page |
| 1024–1535 px | Desktop sidebar and full table; keep inspector as full page unless the content itself has sufficient remaining width |
| 1536 px and above | Table plus right inspector where a usable table width remains; use available width rather than a large fixed central card |

Breakpoints are layout candidates, to be tested at actual container widths and browser zoom. At 320 CSS px the page must remain usable; two-dimensional tables may have labelled local horizontal scrolling, not cause the entire page to overflow. Avoid shrinking all content to fit.

Use minimum heights rather than clipped fixed heights. Long names may wrap or offer a full accessible value; do not use hover-only tooltips to reveal required information. Do not hide source time, limitations or permission scope merely to reduce clutter. Defer configurable density, column persistence and resizable panels until the compact default is proven useful.

## 9. HTMX interaction and state contract

Use full server-rendered pages as the baseline. Add HTMX to filter results, refresh progress and open an authorised detail partial. The browser never becomes the authority for run state, permissions or interpretations.

- Keep stable region IDs and coherent full-page/partial URLs. An old filter response must not overwrite a newer query; cancel or serialise requests with an explicit interaction policy.
- Preserve filters and navigation state in safe URL parameters; avoid putting confidential free-text notes in URLs, browser storage or analytics.
- Mark only the updating region busy. Preserve existing rows while refreshing, retain focus and announce the resulting count when a user changes a filter.
- During first load use a simple placeholder/status message. During subsequent polling keep stable results rather than repeatedly replacing the whole page.
- Announce meaningful phase/completion/failure changes using an appropriate live region; do not read every counter increment.
- On network failure keep previous data with a visible stale indicator and retry action. Never replace it with “No findings”.
- Authentication expiry redirects to login deliberately, rather than inserting a login page into a table. Handle 403/404 without revealing inaccessible object details.
- Do not reorder a focused row during polling. Updated severity can be marked pending refresh; explicit user sorting may reorder.
- Forms require CSRF protection and idempotent server commands where already specified. Disable repeat submission while pending, without making recovery from a failed request impossible.

## 10. Accessibility and language acceptance

Target WCAG 2.2 AA for the implemented UI, with additional project conventions below. Do not claim conformance from automated tests alone.

Normal text must reach 4.5:1 contrast; large text can use the applicable 3:1 threshold, though the proposed palette aims higher for ordinary labels. Interactive boundaries, focus and non-text state indicators need appropriate contrast on their actual surfaces. [W3C contrast guidance](https://www.w3.org/WAI/WCAG22/Understanding/contrast-minimum.html).

WCAG 2.2's minimum target-size criterion includes 24×24 CSS px and defined spacing/other exceptions. For this application, prefer at least 32×32 px desktop icon targets and 40 px main controls, increasing to 44 px for coarse pointers. Compact rows must not make click targets overlap. [W3C target-size guidance](https://www.w3.org/WAI/WCAG22/Understanding/target-size-minimum.html).

Required checks: logical landmarks/headings; skip link; visible unobscured keyboard focus; native table semantics and sort announcements; labelled inputs/errors; usable dialogs; reduced-motion behaviour; 200% zoom and narrow-width reflow; forced-colour/high-contrast review. No drag-only interactions, hover-only explanations or colour-only meaning.

All application-owned labels use message catalogs and language-neutral internal state IDs. UI language and report locale are independent. DE uses Swiss Standard German (`de-CH`). Design for German text expansion: buttons grow, toolbars wrap, error text remains visible. Source evidence, identifiers and analyst notes retain their original language.

Examples of planned terminology:

| EN | DE-CH | Meaning |
|---|---|---|
| Observed infrastructure | Beobachtete Infrastruktur | Publicly observed endpoints, not verified data storage |
| Observed providers | Beobachtete Anbieter | Technical attribution, not a contractual register |
| Coverage | Prüfabdeckung | Scope and checks actually covered |
| Partial results | Teilresultate | Useful but incomplete collection |
| No match for queried URL | Kein Treffer für die geprüfte URL | Scoped reputation result, no safety guarantee |
| Report-only access | Zugriff nur auf diesen Bericht | Exact-version access |
| Transfer to TPRM confirmed | Übertragung ins TPRM bestätigt | Human confirmation, not download status |

## 11. Evidence and PDF presentation

Design choice DS-03: share semantic language, typography hierarchy and severity meaning with the application, but use a dedicated print composition. Do not print the interactive application shell as the evidence report.

Plan A4 portrait for the summary and normal appendix; use a deliberate landscape annex or reduced column set when a technical table needs more width. Repeat table headers, use stable page numbering, retain source/collection times and evidence IDs, and avoid tiny text to force a table onto one page. Long findings may continue across pages with clear context.

Include report ID/version, fixed run window, language, issue/expiry metadata, scope, partial-coverage notices and integrity reference. Screenshots have captions and capture metadata. The DE and EN variants describe the same frozen facts; layout may differ but neither variant silently loses content.

Use text/icons in addition to colour so grayscale printing remains intelligible. Bundle required styles/fonts/images locally for offline rendering. Exclude navigation, interactive controls, inaccessible source links and transient operational messages. Visual token/template changes affect new renderings under the report-version policy, not issued PDF bytes.

## 12. Security and software-design rules

Design inputs and screenshots can be hostile. Templates escape all collected text; no `safe` filter on provider content. Render evidence images from authorised application storage, not live target URLs. No iframe embedding of a target and no remote UI/CDN/font/analytics requests.

Wrap untrusted identifiers in an isolated left-to-right presentation where appropriate. Flag suspicious Unicode/bidirectional controls in display text without changing retained source bytes. Copy actions must copy the full intended identifier, not a visually truncated or misleading string.

Service/preparation logic supplies labels, timestamps, safe links, severity and permitted actions. Jinja may select a presentation variant, but cannot decide business permissions, recompute security findings or fetch related records. Treat CSS/HTML from third parties as content, never as application styling.

Tailwind scans source text for complete class names. Plan explicit source coverage for templates and the small component-variant map, and keep every allowed class literal discoverable. Do not generate values such as `bg-<provider status>-...` from runtime data. [Tailwind source detection](https://tailwindcss.com/docs/detecting-classes-in-source-files).

Use `@theme`, small base styles and ordinary utilities; introduce custom component CSS only where it reduces repeated meaningful behaviour. Keep macro APIs small. Avoid unrestricted `class`, `style`, `hx-*` or event-handler passthrough from untrusted inputs. The UI dependency baseline remains Tailwind and HTMX; no new general-purpose widget framework is planned.

KISS/YAGNI: one light compact theme, no theme editor, no density settings or ornamental charts. DRY: shared tokens/macros for genuinely repeated patterns. SOLID: presentation components have small input contracts; services remain responsible for domain decisions. Least privilege/privacy: server-approved data/actions and scoped evidence views. Trade-off: an in-house component set needs focused accessibility and regression testing; a generic kit does not remove those obligations.

## 13. Prospective file map — only after approval

These paths describe intended work, not files created by this plan. Fit them to the then-current repository and inspect existing work before editing.

| Path | Responsibility |
|---|---|
| `assets/app.css` | Tailwind entry, theme/base integration and explicit source roots |
| `assets/tokens.css` | Approved colour/type/spacing/geometry tokens |
| `assets/report.css` | Dedicated offline print composition using compatible semantic roles |
| `app/templates/base.html` | Landmarks, navigation, locale, local styles and minimal script hooks |
| `app/templates/components/` | Small macro files for actions, fields, statuses, notices, metadata and evidence |
| `app/templates/assessments/` | Overview, filters/table and authorised host-detail partials |
| `app/templates/reports/` | Report UI plus a distinct frozen print-template subtree |
| `app/templates/sharing/` | Assessment/exact-version sharing and effective-access presentation |
| `app/static/css/` | Built application/report CSS; generated, not hand edited |
| `app/static/js/` | Local HTMX and only necessary focus/dialog/progressive-enhancement code |
| `app/static/icons/` | Reviewed local SVG symbols; licence retained if a set is used |
| `app/translations/` | DE/EN application-owned component/report strings |
| `tests/ui/`, `tests/reporting/` | Component states, keyboard/accessibility flows and report visual cases |
| `docs/design/design-system.md` | Approved component/token reference maintained alongside implementation |

The existing package manifest's build command refers to CSS and copy-script paths that do not yet exist. After approval, reconcile the build with this file map and make it reproducible using the existing lockfile. Do not treat that manifest as proof the UI build already works.

## 14. Implementation sequence after explicit approval

| Step | Deliverable | Exit evidence |
|---|---|---|
| DS-1 — foundations | Approved tokens, typography, density and local Tailwind build | Repeatable build, no CDN; actual-state contrast checks; classes used by variants present in output |
| DS-2 — primitives | Buttons, fields, badges, notices, metadata and dialogs | Synthetic component gallery covering normal/focus/disabled/pending/error/long-DE states; keyboard checks |
| DS-3 — analyst workspace | Shell, summary blocks, filters, host table and responsive detail composition | Usable at narrow/laptop/wide widths; filters and focus survive updates; permission-specific view models |
| DS-4 — evidence and report views | Finding/evidence presentation, DE/EN report composition and report-only layout | Identical report facts, print/grayscale review, no source-case leakage |
| DS-5 — workflow integration | HTMX states, sharing/access expiry, provider errors and manual handoff presentation | No stale-response overwrite, misleading empty state or incorrect permission action |
| DS-6 — verification/documentation | Regression cases and approved component reference | Acceptance checklist passed; remaining limitations documented honestly |

Dependencies: DS-1/2 may use synthetic fixtures once approved; real private screens require the application's authentication/access milestone, and real scan/report workflows require their respective services. A synthetic gallery must be labelled and local/development-only, never presented as a working scanner. Do not build production domain logic solely to demonstrate design components.

## 15. Acceptance checklist and plan review

- [ ] User explicitly approves this plan before implementation starts.
- [ ] Compact desktop workspace remains readable without shrinking core text below 14 px.
- [ ] All status dimensions and evidence limitations retain their separate meanings.
- [ ] Tables support long hosts, IPv6, mixed endpoints, stale data, no matches and unavailable checks.
- [ ] Keyboard/focus behaviour survives filtering, polling, dialogs and inspector navigation.
- [ ] Rendered contrast/targets/reflow pass the specified checks; automated checks supplemented by manual review.
- [ ] No hidden content, inaccessible counts or source artifacts leak through report-only UI/partials.
- [ ] DE strings wrap correctly; report language and UI preference remain independent.
- [ ] DE/EN PDFs use the same frozen facts and work without online assets or live application links.
- [ ] Templates use complete allowlisted Tailwind classes and small documented macro contracts.
- [ ] No runtime implementation details appear in normal user flows unless useful for a decision.
- [ ] UI assets make no third-party requests; collected content is escaped and treated as untrusted.
- [ ] Reusable components and print styles have realistic synthetic failure-state regression examples.

Plan review performed before delivery: checked scope against the technical-only architecture, adapted skill patterns to Jinja, incorporated the confirmed density preference, calculated sample palette contrast, and distinguished future acceptance tests from completed validation. No application accessibility or visual-rendering test has been performed because this deliverable is a Markdown plan.

## 16. Approval scope

Requested approval covers the compact light visual direction, token baseline, component/page contracts, responsive behaviour, dedicated DE/EN print layout and staged implementation approach. Colours/sizes remain proposed until that approval. The user may request edits instead.

**Stop after delivering this plan. Wait for explicit approval before creating or changing CSS, templates, JavaScript, build scripts, application code or dependencies.** This gate comes directly from the user's current instruction. Approval of this design-system plan would not by itself approve production deployment, live target collection or publication.
