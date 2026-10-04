# Vendored presentation assets

No project open-source licence has been selected; that remains a Phase 2 decision. The following third-party licences must remain with distributions that contain their assets.

| Asset | Version/source | Licence location |
|---|---|---|
| Tailwind CSS / CLI | 4.3.3, existing npm lockfile | MIT; `app/static/licenses/tailwindcss.txt` copied by asset build |
| HTMX | 2.0.11, existing npm lockfile | Zero-Clause BSD; `app/static/licenses/htmx.txt` copied by asset build |
| Inter static regular / semibold | [Official Inter v4.1 font files](https://github.com/rsms/inter/tree/v4.1/docs/font-files) | SIL Open Font License 1.1; `app/static/fonts/LICENSE.txt` |

Inter files were retrieved from the official `rsms/inter` repository at tag `v4.1` on 2026-10-02. They are bundled, never loaded from a remote font service. SHA-256:

```text
Inter-Regular.woff2  e06f6b1bc553aaea4e4668023ed0ab0a147129c3107f511bc7d03d361b0ae085
Inter-SemiBold.woff2 5cb7103e4e605989afebc03d989c79201e54b21b5183db33981f70db9178a301
```

The SVG interface icons and synthetic page illustration were authored for this repository and do not copy an icon kit or third-party screenshot. Python dependency licences remain governed by their installed package metadata and `uv.lock`; this page inventories vendored presentation assets, not a complete dependency SBOM.
