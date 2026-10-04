# Design-system validation record

Date: 2026-10-02. Scope: the approved compact analyst **presentation preview**, not the production due-diligence platform. Runtime: Windows, Python 3.12, Node 24, installed Edge 153. All example targets use reserved names/addresses. No provider APIs or live targets were contacted.

## Executed checks

| Check | Result |
|---|---|
| `npm run build` | Passed; local Tailwind 4.3.3 bundle, copied HTMX 2.0.11, print CSS and licence notices |
| Python catalog compiler | Passed; Swiss German gettext catalog compiled without catalog validation errors |
| Ruff lint and formatting | Passed for application, tests and catalog build script |
| Strict mypy | Passed for all 6 Python application modules |
| Pytest | **39 passed**, socket access disabled |
| Chromium browser checks | **54 passed**, including all 11 workspace pages in DE at 320, 768, 1280 and 1680 CSS pixels |
| Rendered component contrast | Tested action and badge foreground/background combinations all exceed 4.5:1; primary action 5.47:1 |
| Runtime page resources | No external page requests; no unexpected JavaScript/CSP errors during successful checks |
| Report PDFs | DE and EN each render as **two A4 pages** using local static fonts; all four pages rasterised and visually inspected |

Python commands, from the repository root:

```powershell
.\.venv\Scripts\python.exe scripts\build-translations.py
.\.venv\Scripts\python.exe -m ruff check app tests scripts\build-translations.py
.\.venv\Scripts\python.exe -m ruff format --check app tests scripts\build-translations.py
.\.venv\Scripts\python.exe -m mypy app
.\.venv\Scripts\python.exe -m pytest -q -p no:cacheprovider
```

The `no:cacheprovider` switch works around a Windows sandbox restriction on pytest's temporary-directory chmod. It does not disable application checks or change their assertions. Static-file test responses are explicitly closed; resource warnings remain errors.

Start the preview as described in [the implementation guide](design-system.md), then run:

```powershell
node scripts\verify-preview.mjs
pdfinfo .local\verification\report-de-CH.pdf
pdftoppm -scale-to 1200 -png .local\verification\report-de-CH.pdf .local\verification\report-de
pdftoppm -scale-to 1200 -png .local\verification\report-en.pdf .local\verification\report-en
```

The browser test uses Node's built-in WebSocket and an installed Chromium browser, not an added frontend testing dependency. `BROWSER_PATH` can select another local Chromium executable; `PREVIEW_URL` must remain loopback. It launches a separate hidden headless process/profile and closes that browser when finished. In this environment browser startup required execution outside the restricted sandbox. No sandbox-disabling browser flags were used.

Generated evidence stays in ignored `.local/verification/`: browser JSON results, screenshots and the two synthetic PDFs. It is not an issued business report, source fixture or distributable application asset. Browser profiles are isolated beneath `.local/browser-profiles/`.

## What the tests establish

- All workspace pages render in EN and DE with unique IDs. Browser layout checks find no page-wide horizontal overflow at the four tested widths; data tables retain local scrolling.
- Loopback and trusted-host restrictions reject nonlocal requests; spoofed forwarded addresses do not bypass them. No production case route or mutation endpoint is exposed.
- Query enums/lengths are validated. Host filtering and HTMX partial responses preserve separate result/severity semantics. Provider-like markup and search input are escaped.
- Denied, expired, failed and loading result states do not include host rows. Ineligible TLS fixtures contain no screenshot element.
- DE/EN report HTML contains the same structured host facts. Recipient/print links remain inside the exact report version and local assets, without case IDs, raw IP evidence or future report versions.
- HTMX filter replacement preserves focus and unique target IDs; consecutive requests display the latest filter. Wide-screen inspector opening moves focus to its heading; closing restores the host link. Narrow screens navigate to the full host page.
- A deliberately disconnected browser keeps the previous rows and reveals an explicit refresh-failure notice. This caught and fixed the distinction between HTTP failure (`detail.failed`) and HTMX transport events (`sendError`/`timeout`). Cancelled superseded requests do not become failure notices.
- Native dialog initial focus, Escape dismissal and return focus work in the tested browser. With scripting disabled, the server-rendered filtered inventory remains readable.
- The report uses its bundled font, has no workspace navigation in print and preserves textual status meaning. Visual review covered wrapping, screenshot captions, page numbering, whitespace and both language layouts.

## Issues found and resolved

1. An intrinsic grid width caused evidence content to overflow at 320 px. Grid children/panels now allow shrinking and headings wrap.
2. HTMX network failures do not populate the HTTP failure flag. Explicit transport-error handling now exposes the stale-results message.
3. The screen footer created an almost empty third PDF page. Print output now uses the repeated margin footer exclusively.
4. The initial variable font caused Poppler glyph warnings. Static Inter regular/semibold files removed those warnings in the final PDF render.

## Limits and remaining acceptance work

This is not a WCAG certification. Full screen-reader testing, native 200% browser zoom, forced-colour mode, touch-device operation, comprehensive non-text contrast/target-size auditing and alternate-browser print behaviour remain manual acceptance work. Reduced-motion/forced-colour rules and semantic controls are present, but were not exhaustively tested across assistive technologies.

The synthetic sample is small. Real-volume pagination, mixed endpoint aggregation, report pagination for large appendices and all production role/state combinations require later backend integration fixtures. The simplified preview does not establish authentication, RBAC, storage segregation, retention deletion, immutable reports, four-eyes review, licensed exports, audit logging, provider budgets, backup recovery or collector isolation.

DS-1 through DS-4 have reusable presentation implementations. DS-5 is implemented only for local read-only interactions and demonstration states; real sharing, polling, report issuance and manual TPRM confirmation depend on the planned services. DS-6 has the checks recorded here, with the accessibility/manual items above still open. Do not mark the platform's M0–M7 milestones complete from this design-system work.
