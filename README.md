# VAPT Lens

A guided, **read-only** security-testing assistant for your browser. Open any website you are authorized to test, click the VAPT Lens icon, and get a live breakdown of the page's attack surface plus step-by-step **what to test and how** cards powered by **Claude Red (`offensive-*`) skills via OpenCode**.

[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Node](https://img.shields.io/badge/node-%3E%3D20-brightgreen.svg)](package.json)

> [!WARNING]
> **Authorized testing only.** VAPT Lens never sends attack payloads, never submits forms, never logs in, and never scans hosts outside the site you are viewing. It only reads page structure and your imported Burp metadata, then gives you manual testing guidance. Use it only on systems you own or have written permission to test. See [docs/SAFETY.md](docs/SAFETY.md).

---

## Prerequisites (What you need on your PC)

Before setting up VAPT Lens on a new computer, make sure you have:

1. **Node.js 20 or newer** — required to build the extension and run the local helper service.
   - Check in a terminal: `node -v` (should show `v20.x.x` or higher).
   - Install from [nodejs.org](https://nodejs.org/) if missing.
2. **Git** — to download the project (or download the ZIP from GitHub instead).
3. **A supported browser**:
   - **Chrome, Chromium, Brave, or Edge** (version 116+), **or**
   - **Firefox** (version 115+).
4. **OpenCode + Claude Red skills (recommended for full guidance)**:
   - VAPT Lens compiles its offline testing cards from **Claude Red (`offensive-*`) skills** installed for **OpenCode** (by default in `~/.config/opencode/skills`), and uses **OpenCode** (`opencode` CLI) for live AI-tailored hints.
   - Make sure `opencode --version` works in your terminal and your Claude Red `offensive-*` skill folders are in place.
   - *Without OpenCode / Claude Red skills:* the extension and helper still install and map the page's attack surface, passive header checks, and site map, while the guided test cards remain minimal/empty until you add skills.
5. **Optional — Burp Suite Community**:
   - Only needed if you want to stream live proxy traffic or paste exported Burp XML / HAR / `curl` requests into the **Burp traffic** tab.

---

## Step-by-step Setup (Fresh PC)

No third-party npm packages are required — everything runs with built-in Node.js modules.

### Step 1: Download the project

```sh
git clone https://github.com/HavocReaper/vapt-lens.git
cd vapt-lens
```

*(If you don't use Git, click **Code → Download ZIP** on GitHub, unzip it, and open a terminal inside the extracted `vapt-lens` folder.)*

### Step 2: Build the knowledge base & extension

```sh
npm run build
```

This does two things automatically:
1. Reads your **Claude Red (`offensive-*`) skills** from `~/.config/opencode/skills` and compiles them into a local knowledge base.
2. Builds ready-to-load browser packages in `dist/chrome/` and `dist/firefox/`.

> **Skills stored in a custom folder?** Point the builder at your folder before building:
> - **macOS / Linux:** `VAPT_LENS_SKILLS_DIR=/path/to/skills npm run build`
> - **Windows (PowerShell):** `$env:VAPT_LENS_SKILLS_DIR="C:\path\to\skills"; npm run build`

*(If no skills folder is found yet, `npm run build` still succeeds with a warning so you can finish installing the extension and run `npm run kb` later.)*

### Step 3: Load the extension in your browser

**Chrome / Chromium / Brave / Edge**
1. Open `chrome://extensions` in your address bar.
2. Turn **Developer mode** on (top-right toggle).
3. Click **Load unpacked**.
4. Select the **`dist/chrome`** folder inside your `vapt-lens` directory.
5. Click the puzzle-piece icon in the toolbar and **pin VAPT Lens** so the icon is always visible.

**Firefox**
1. Open `about:debugging#/runtime/this-firefox` in your address bar.
2. Click **Load Temporary Add-on…**.
3. Open the **`dist/firefox`** folder and select **`manifest.json`**.

*(Note: Firefox clears temporary add-ons when you close the browser — just repeat Step 3 when you reopen Firefox.)*

### Step 4: Start the local helper service

Keep one terminal window open inside the `vapt-lens` folder and run:

```sh
npm run bridge
```

Leave this terminal running while you test. Your browser extension talks only to this helper running on your own machine — nothing is ever sent to any external VAPT Lens server. You do **not** need to enter any local address or URL anywhere; the extension finds the helper automatically.

---

## How it works on an actual website (After clicking the icon)

Once the helper is running and the extension is loaded:

1. **Open your target website** in a normal browser tab (for example, your own test app, local lab, or an authorized bug-bounty target).
2. **Look for the floating VAPT Lens orb** in the corner of the webpage, or **click the VAPT Lens icon** in your browser toolbar.
3. **Click the orb / icon**:
   - The **VAPT Lens side panel** slides open alongside the webpage.
   - It immediately performs a **read-only structural scan** of the page you are viewing — inspecting forms, input field names, URL query parameter names, links, scripts, endpoints, cookie names, and security header names.
   - It **never** reads passwords, field values, tokens, cookie values, or keystrokes.
4. **Confirm authorization**:
   - At the top of the panel, tick **"I'm authorized to test this target"**. This safety gate unlocks the **Guided tests** cards.
5. **Choose how deep you want to go** using the top buttons:
   - **Scan page** — Re-reads the current tab (click this whenever you navigate to a new page, open a modal, or log into a new area).
   - **Crawl site** — Runs a polite, bounded, **GET-only** walk of links on the same site to discover additional pages, forms, and parameters.
   - **Scan whole site** — Runs the site crawl and builds a combined site map and finding summary with a live progress bar.
   - **AI hints (toggle)** — When enabled, sends redacted structural metadata (host, paths, parameter *names*, and tech stack — never values) to your local **OpenCode** CLI using **Claude Red skills** to generate tailored test ideas for that specific page.

### What you see in each tab

| Tab | What it gives you |
| --- | --- |
| **Overview** | Snapshot of the target host, detected technologies, counts of forms/inputs/parameters/endpoints, and top focus areas. |
| **Attack surface** | Every form, input field, URL parameter, cookie name, DOM sink, and endpoint on the current page — along with its **CSS selector / XPath** so you know exactly where it lives. |
| **Site map** | Tree of every page, form, input, and parameter discovered by **Crawl site** or **Scan whole site**. |
| **Security checks** | Passive audit of response security headers (`CSP`, `HSTS`, `X-Frame-Options`, `X-Content-Type-Options`, `Referrer-Policy`, `Permissions-Policy`) plus copy-only manual commands for TLS/port checks. |
| **OWASP Top 10** | Breakdown of how the page maps onto OWASP 2021 categories (`A01`–`A10`). |
| **Guided tests** | Prioritized manual test cards built from your **Claude Red skills** (and optional OpenCode AI hints). Filter by OWASP category, test category, or keyword. Each card tells you *why it applies here*, *what to test manually*, *safe copyable test strings*, *what to look for*, and the source skill. |
| **Burp traffic** | Automatically lists passive browser request metadata, or lets you paste Burp XML, HAR files, `curl` commands, or URL lists (values are stripped automatically). |
| **Notes** | Per-host scratchpad saved only in your browser, with one-click **Export Markdown** for your report. |

---

## Configuration (Optional)

The local helper reads `bridge/config.json` if present. To customize defaults, copy [`bridge/config.example.json`](bridge/config.example.json) to `bridge/config.json`:

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
| `aiEnabled` | Enables or disables local OpenCode AI hints (on by default). |
| `model` | Informational — OpenCode uses whichever model you already configured in OpenCode. |
| `port` | Internal helper port — advanced option only. Leave the default so the extension connects automatically. |
| `burpLive` | Accepts passive/live Burp traffic metadata. |

You can also toggle **AI hints** directly inside the extension panel.

## Burp Suite integration (Optional)

Because Burp Suite Community has no built-in REST API, VAPT Lens supports:
- **Live traffic** using the optional Jython feeder (`burp/burp_to_bridge.py`), or
- **Copy/paste exports** (Burp site-map/proxy XML, HAR files, or `curl` commands) in the **Burp traffic** tab.

Only method, host, path, parameter/header **names**, status code, and content type are kept. See [docs/BURP.md](docs/BURP.md) for the full Burp setup guide.

## Useful commands

| Command | What it does |
| --- | --- |
| `npm run build` | Compile your Claude Red skills into the KB and build Chrome + Firefox extensions. |
| `npm run kb` | Rebuild only the knowledge base after adding or updating skills. |
| `npm run bridge` | Start the local helper service required by the extension. |
| `npm test` | Run all 55 unit and integration tests. |
| `npm run smoke` | Start the helper on a spare port and verify its API end-to-end. |

## Project layout

```
extension/        Chrome MV3 + Firefox MV3, shared source with two manifests
  src/core/       Browser-agnostic scanning, analysis and header checks
bridge/           Local Node service: KB, analysis, Burp import, OpenCode AI bridge
  lib/            crawl, analyze, burp, site-findings, ai, util
scripts/          Knowledge-base compiler and extension package builder
burp/             Optional Burp Community Jython traffic forwarder
docs/             Burp and safety guides
test/             Cross-component integration tests
```

## Troubleshooting

| Symptom | Fix |
| --- | --- |
| Panel says the helper/bridge is offline | Make sure `npm run bridge` is running in your terminal. |
| **Guided tests** tab asks for authorization | Tick **"I'm authorized to test this target"** at the top of the panel. |
| **Guided tests** tab has no cards | Make sure your Claude Red (`offensive-*`) skills are in `~/.config/opencode/skills` (or set `VAPT_LENS_SKILLS_DIR`) and run `npm run kb`, then reload the extension if needed. |
| AI hints don't appear | Check that `opencode --version` works in your terminal and **AI hints** is checked in the panel. Offline skill cards still work without it. |
| Extension disappeared in Firefox | Firefox removes temporary add-ons on browser restart — reload `dist/firefox/manifest.json` from `about:debugging`. |
| Burp feeder shows Python errors | Use Jython **2.7.5rc1 standalone** with Java 17/21/25. See [docs/BURP.md](docs/BURP.md). |

## Development

```sh
npm test          # 55 tests (Node built-in test runner)
npm run build     # rebuild KB + browser packages
npm run smoke     # end-to-end helper check
```

To enable GitHub Actions CI in your own fork/repo, copy [docs/ci.yml](docs/ci.yml) to `.github/workflows/ci.yml`.

## Safety

Guidance only — no attacks are performed, no secret values are stored or transmitted, and all processing stays on your machine. Read [docs/SAFETY.md](docs/SAFETY.md) before testing any target.

## License

[MIT](LICENSE) © 2026 HavocReaper
