# Safety, privacy and usage policy

VAPT Lens is a **guided, read-only assistant**. It observes the current page, can perform
a bounded GET-only walk of the same origin (including passive discovery of routes in
same-host JavaScript bundles for single-page apps), optionally reads Burp/browser request
metadata, and suggests **what to test and how** — including OWASP Top 10 mappings tied to
the exact URL and exact point (parameter, form field, header or DOM sink) where each
finding applies.

## Authorized testing only

- Use this tool **only on systems you own or are explicitly authorized to test**.
- Follow the engagement's **scope and rules of engagement** at all times. Stay inside
  the approved hosts, paths and time windows; stop if you leave scope.
- You must check **"I'm authorized to test this target"** in the panel before cards are
  shown. This is an acknowledgement, not a technical control — the responsibility is yours.

## Guidance only — no attacks performed

- VAPT Lens **never sends attack payloads, never exploits, never logs in**, and never
  modifies the page or the target.
- The optional **Crawl site** / **Scan whole site** action only performs normal GET
  navigations/fetches to the **same hostname**, follows at most 12 pages to depth 2,
  passively reads same-host JavaScript bundles for SPA route names (without executing
  JavaScript), skips links whose names suggest destructive actions (logout, delete,
  reset, checkout, etc.), and **never submits forms**. Progress is shown in the panel.
- Cards describe manual steps to try yourself in Burp or the browser. Any "payloads"
  shown are copyable safe test strings for you to use, not requests the tool executes.
- Findings from the site scan and from captured Burp traffic are hints, not proof. Each
  one is tied to an **exact URL and point** (such as a parameter name or header) so you
  can verify it manually in the browser or Burp Repeater, then report responsibly.

## What stays local

- Page observations, imported Burp traffic, notes, and configuration are processed by
  the **local helper running on your own computer** and stored locally (e.g. browser
  `chrome.storage.local`). You never need to configure or enter a local address.
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
- AI hints can be switched off at any time: just uncheck **AI hints** in the panel.
  With AI off, nothing is sent to the AI service; local skill cards still work.

## Clearing data

- **Clear imported traffic:** in the panel's **Burp traffic** tab use **Clear**.
  Restarting the helper also clears in-memory traffic.
- **Clear notes:** use **Clear notes** in the panel, or remove the corresponding
  `chrome.storage.local` entries. Notes never leave the browser.
- **Unload the Burp extension:** Extender > Extensions > select `VAPT Lens Bridge
  Feeder` > Remove.

## Reminder

Test responsibly, minimize data collection, and respect the scope, rules of engagement,
and any legal or organizational policies that apply to your engagement.
