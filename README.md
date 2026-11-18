# VAPT Lens

A guided, **read-only** security-testing assistant for the browser. It is a floating overlay that observes the page you are on, optionally reads Burp Suite traffic you import, and tells you **what to test and how** — turning a local library of `offensive-*` security skills into actionable, OWASP-mapped test cards.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](package.json)

> [!WARNING]
> **Authorized testing only.** VAPT Lens does not send attack payloads, scan other hosts, exploit anything, or log in anywhere. It reads the current page and locally imported Burp metadata, then produces a testing guide. Use it only on systems you own or are explicitly authorized to test. See [docs/SAFETY.md](docs/SAFETY.md).

## What it does

- **Floating overlay** in Chrome/Chromium and Firefox — one click opens the guided side panel.
- **Same-origin site crawl** — GET-only, bounded, read-only walk of the current site, producing an inventory of forms, input fields, URL parameters and endpoints with their **CSS selectors / XPath locations**.
- **Attack surface view** — a structured map of everything the page exposes, including field locations and URL parameter origins.
- **OWASP Top 10 mapping** — every guided test is tagged with an OWASP 2021 category (A01–A10), with a dedicated OWASP view and filters.
- **Passive security checks** — evaluates captured security headers (CSP, HSTS, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy) and gives you copy-only manual commands for port and TLS/cipher checks. Lens never runs those scans itself.
- **Guided test cards** — what to try manually, why it applies here, copyable safe test strings, what to look for, and the source skill.
- **Burp Community support** — live traffic through an optional Jython feeder, plus passive collection of browser request metadata and pasted XML/HAR/curl exports.
- **Hybrid guidance** — offline cards compiled from your local `offensive-*` skills, with AI-tailored cards via your local OpenCode service (on by default, local-only).
- **Local notes** per host and Markdown export.

## What it does not do

No active scanning, fuzzing, exploitation, credential attacks, or remote telemetry. The extension never calls a remote service — it talks only to `http://127.0.0.1:8787`, the local bridge you run yourself.

## Requirements

| Requirement | Notes |
| --- | --- |
| **Node.js 20+** | Runs the bridge and the build scripts. No npm dependencies to install. |
| **Chrome/Chromium 116+** or **Firefox 115+** | MV3 side panel (Chrome) / sidebar (Firefox). |
| **Optional:** `opencode` CLI | Only for AI-tailored cards. Without it, offline skill cards still work. |
| **Optional:** `offensive-*` skills | The knowledge base is compiled from your own skill library. Without it the app runs, but guided cards are empty. |
| **Optional:** Burp Suite Community | For live traffic via the Jython feeder, or import exports manually. |

## Installation

### 1. Clone and build

```sh
git clone https://github.com/HavocReaper/vapt-lens.git
cd vapt-lens
npm run build
```

`npm run build` does two things:

1. `scripts/build-kb.mjs` compiles every `offensive-*/SKILL.md` under `~/.config/opencode/skills` into `bridge/data/knowledge-base.json`.
2. `scripts/build-extensions.mjs` produces loadable packages in `dist/chrome/` and `dist/firefox/`.

If you keep your skills somewhere else, point the builder at that directory:

```sh
VAPT_LENS_SKILLS_DIR=/path/to/skills npm run kb
```

If the directory does not exist yet, the build still succeeds and writes an empty knowledge base with a warning — you can regenerate it later with `npm run kb`.

### 2. Load the extension

**Chrome / Chromium / Edge**

1. Open `chrome://extensions`.
2. Enable **Developer mode**.
3. Click **Load unpacked** and select the `dist/chrome` folder.
4. Pin **VAPT Lens** to the toolbar.

**Firefox**

1. Open `about:debugging#/runtime/this-firefox`.
2. Click **Load Temporary Add-on…**.
3. Select `dist/firefox/manifest.json`.

Firefox temporary add-ons are removed when the browser restarts; reload the manifest to re-enable it.

### 3. Start the local bridge

```sh
npm run bridge
```

You should see:

```
VAPT Lens bridge listening at http://127.0.0.1:8787
```

Verify it from another terminal:

```sh
curl http://127.0.0.1:8787/api/health
```

The bridge binds to `127.0.0.1` only. To use a different port:

```sh
PORT=9000 npm run bridge
```

> The extension is hard-wired to port `8787`. If you change the port, the panel will show the bridge as offline.

### 4. First run

1. Browse to a page you are authorized to test.
2. Click the shield orb, tick **I'm authorized to test this target**, and press **Scan**.
3. Open **Guided tests** for OWASP-mapped cards, or click **Crawl site** for a bounded GET-only walk.
4. The **Site map** tab then lists every discovered form, input, URL parameter and endpoint with its selector/XPath.

## Configuration

The bridge reads `bridge/config.json` if it exists (created from [`bridge/config.example.json`](bridge/config.example.json)):

```json
{
  "aiEnabled": true,
  "model": null,
  "port": 8787,
  "burpLive": true
}
```

| Key | Meaning |
| --- | --- |
| `aiEnabled` | Gate the local AI layer. On by default; everything is local. |
| `model` | Informational only — AI runs through your existing `opencode` configuration. |
| `port` | Used when the `PORT` environment variable is unset. |
| `burpLive` | Accept passive/live Burp traffic on `/api/burp/stream`. |

Settings can also be changed at runtime through the panel (`GET`/`POST /api/config`).

## AI cards (optional)

AI mode shells out to your installed OpenCode CLI with a redacted prompt — host, path, parameter *names*, technologies and status codes only. No token, cookie or header values are included.

```sh
# make sure the CLI is on your PATH and has a model configured
opencode --version
npm run bridge
```

If the CLI is missing, the panel silently falls back to offline skill cards; nothing breaks.

## Burp Suite

Burp Community has no REST API, so VAPT Lens supports three paths: the optional Jython forwarder for live traffic, pasted site-map/proxy XML, and pasted HAR or `curl` commands. Only method, path, parameter/header **names**, status and content type are used. See [docs/BURP.md](docs/BURP.md) for the full walkthrough, including the 2026 Jython/Java version notes.

## Commands

| Command | What it does |
| --- | --- |
| `npm run bridge` | Start the local bridge (default `127.0.0.1:8787`). |
| `npm run kb` | Regenerate the knowledge base from installed skills. |
| `npm run build` | Regenerate the KB and build both browser packages. |
| `npm test` | Run the unit and integration tests (Node's built-in test runner). |
| `npm run smoke` | Boot the bridge on a spare port and exercise its API end to end. |

## Project layout

```
extension/        Chrome MV3 + Firefox MV3, shared source with two manifests
  src/core/       Browser-agnostic scanning, analysis and header checks
bridge/           Local Node JSON service: KB, analysis, Burp import, optional AI
  lib/            crawl, analyze, burp, site-findings, ai, util
  test/           Bridge unit + integration tests
scripts/          Builders for the knowledge base and extension packages
burp/             Optional Burp Community Jython traffic forwarder
docs/             Burp and safety guides
test/             Cross-component integration tests
```

The extension never calls a remote service. It talks only to the local bridge; the bridge talks only to your local filesystem and (optionally) your local `opencode` binary.

## Development

```sh
npm test          # 52 tests: extension core, bridge, integration
npm run build     # rebuild KB + both extension packages
npm run smoke     # end-to-end bridge API check
```

There are no third-party dependencies, so there is nothing to `npm install`. Tests use `node --test`, so Node 20+ is all you need.

To enable continuous integration, copy [docs/ci.yml](docs/ci.yml) to `.github/workflows/ci.yml` and push it with a token that has the `workflow` scope — GitHub rejects workflow files from tokens without it. The workflow runs the test suite, the build and the smoke test on Node 20, 22 and 24.

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Panel says the bridge is offline | Start `npm run bridge`; check `curl http://127.0.0.1:8787/api/health`. |
| Guided tests tab is empty | The knowledge base has no skills: run `npm run kb` with your `offensive-*` skills installed, or set `VAPT_LENS_SKILLS_DIR`. |
| AI hints never appear | Ensure `opencode` is on `PATH` and configured, and that `aiEnabled` is true in the bridge config. |
| Extension won't load in Firefox after restart | Temporary add-ons are unloaded on restart — reload `dist/firefox/manifest.json`. |
| Burp feeder shows Python errors | Use Jython **2.7.5rc1 standalone** with Java 17/21/25, not CPython or the installer JAR. See [docs/BURP.md](docs/BURP.md). |
| Crawl finds few pages | The crawler is bounded and same-origin by design; raise the page cap only on sites you own. |

## Safety

Guidance only. No attacks are performed, no secret values are stored or transmitted, and AI runs locally by default. Read [docs/SAFETY.md](docs/SAFETY.md) before using Lens on anything you do not own.

## License

[MIT](LICENSE) © 2026 HavocReaper

VAPT Lens is a testing aid, not a substitute for judgment or a signed scope agreement. You are responsible for staying inside your authorization.
