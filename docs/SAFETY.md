# Safety, privacy and usage policy

VAPT Lens is a **guided, read-only assistant**. It observes the current page, can perform
a bounded GET-only walk of the same origin, optionally reads Burp/browser request metadata,
and suggests **what to test and how** — including OWASP Top 10 mappings.

## Authorized testing only

- Use this tool **only on systems you own or are explicitly authorized to test**.
- Follow the engagement's **scope and rules of engagement** at all times. Stay inside
  the approved hosts, paths and time windows; stop if you leave scope.
- You must check **"I'm authorized to test this target"** in the panel before cards are
  shown. This is an acknowledgement, not a technical control — the responsibility is yours.

## Guidance only — no attacks performed

- VAPT Lens **never sends attack payloads, never exploits, never logs in**, and never
  modifies the page or the target.
- The optional **Crawl site** action only performs normal GET navigations/fetches to the
  **same hostname**, follows at most 12 pages to depth 2, skips links whose names suggest
  destructive actions (logout, delete, reset, checkout, etc.), and **never submits forms**.
- Cards describe manual steps to try yourself in Burp or the browser. Any "payloads"
  shown are copyable safe test strings for you to use, not requests the tool executes.
- Findings are hints, not proof. Verify everything manually and report responsibly.

## What stays local

- Page observations, imported Burp traffic, notes, and configuration are processed by
  the **local bridge** on `127.0.0.1` and stored locally (e.g. browser `chrome.storage.local`).
- The offline knowledge base and rule engine run locally. No telemetry is sent anywhere.

## What is redacted / never captured

- The scanner reads **names, types and lengths only** — never form field values,
  `document.cookie` values, or localStorage/sessionStorage values.
- Query and body parameters are captured as **names only**; values are discarded.
- Headers are limited to an allowlist (content-type, x-frame-options,
  content-security-policy, strict-transport-security, server, x-powered-by,
  cache-control, plus a few other non-sensitive headers); anything containing
  `token|key|secret|auth|session|bearer` is redacted. Cookie and auth headers are
  never included.
- Paths are truncated (300 chars in the Burp extension); inline script evidence is
  truncated to 160 chars. Bodies are never transmitted by the Burp extension.

## AI mode

- When **AI mode is on**, the bridge sends **redacted metadata only** to the **local
  OpenCode service** via `opencode run`. Cookie/header values are dropped, only
  names/flags/booleans remain, and the input is truncated (~12k chars). No raw values,
  cookies, tokens or credentials are included.
- If the local AI call fails, the bridge falls back to local rule cards and shows a
  warning. Local guidance works without it.
- AI hints are **on by default** in v2. **To disable AI:** uncheck **AI hints** in the
  panel, or `POST /api/config` with `{"aiEnabled": false}`. With AI off, nothing is sent
  to the AI service.

## Clearing data

- **Clear imported traffic:** in the panel's **Burp traffic** tab use **Clear**, or call
  `DELETE /api/burp/traffic?host=<host>` (omit `host` to clear all). Restarting the
  bridge also clears in-memory traffic.
- **Clear notes:** use **Clear notes** in the panel, or remove the corresponding
  `chrome.storage.local` entries. Notes never leave the browser.
- **Unload the Burp extension:** Extender > Extensions > select `VAPT Lens Bridge
  Feeder` > Remove.

## Reminder

Test responsibly, minimize data collection, and respect the scope, rules of engagement,
and any legal or organizational policies that apply to your engagement.
