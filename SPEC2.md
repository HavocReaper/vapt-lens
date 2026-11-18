# VAPT Lens v2 — scope expansion (read-only)

Everything stays **guidance-only**. No attacks, no form submissions, no logins, no
payload sending. Crawling is GET-only, same-origin, bounded, and skips risky links.

## 1. Extended PageObservation (scanner)

Add to each form:
- `selector` (stable CSS selector), `xpath`, `index`
- fields gain `selector`, `xpath`

Add top-level `inputs[]`: every input/textarea/select flattened with
`{ page, name, type, id, selector, xpath, formSelector }`. Never values.

Query params gain `location: 'query'` and `page` (URL without query values).

## 2. Crawl API (bridge)

`POST /api/crawl` `{ url, maxPages=12, maxDepth=2 }` →

```
{
  startUrl, host,
  pages: [{ url, status, title, observation: PageObservation|null, error? }],
  inventory: {
    forms: [{ page, action, method, selector, xpath, fields: [...] }],
    inputs: [{ page, name, type, id, selector, xpath, formSelector }],
    urlParams: [{ page, name }],
    endpoints: [{ page, url, source }]
  },
  stats: { pagesCrawled, skipped, maxPagesReached },
  warnings: []
}
```

Crawler rules:
- http/https only; same hostname as start URL; skip fragments; dedupe by path.
- Skip hrefs matching `logout|signout|delete|remove|destroy|reset|submit|pay|checkout|admin/delete|/api/` with mutation-looking words. Never submit forms.
- Bounded: max 12 pages, max depth 2, 250 ms delay between requests, 8 s timeout, 1 MB body cap.
- Regex HTML parsing (no new deps). Extract form/action/method, input/textarea/select names, links, script src, and simple endpoint strings.
- Never keep response bodies, header values, or param values.

## 3. OWASP Top 10 mapping

Each analysis card gains `owasp: { id: 'A03', name: 'Injection' }`.
`AnalysisResponse.summary.owasp` = array of `{ id, name, cardCount }` for all 10 categories.

Mapping (2021):
A01 Broken Access Control: idor, auth, business-logic, csrf, jwt, oauth
A02 Cryptographic Failures: crypto, tls, jwt, session, headers
A03 Injection: sqli, xss, ssti, command, xxe, deserialization
A04 Insecure Design: business-logic, race-condition, workflow
A05 Security Misconfiguration: headers, debug, config, cloud, container, default
A06 Vulnerable Components: dependency, supply-chain, cve, c2, framework
A07 Auth Failures: auth, login, jwt, oauth, session, brute
A08 Software/Data Integrity: deserialization, supply-chain, ci, webhook, jwt
A09 Logging & Monitoring Failures: logging, recon, exfil, persistence
A10 SSRF: ssrf, url-param, redirect, fetch, webhook

Apply in both `bridge/lib/analyze.mjs` and `extension/src/core/analyzer.js`.

## 4. Always-on AI and traffic

- `bridge/config.json` default `{ aiEnabled: true, model: null, port: 8787, burpLive: true }`.
- Panel initial `ui.config.aiEnabled = true`; scan always sends `ai: true` unless user unchecks.
- Background passively collects request metadata via `webRequest` for the current tab:
  method, URL path, query/body param **names**, status, content type — never values.
  POST to `/api/burp/stream` with `source: 'browser-passive'`.
- Panel polls traffic for the current host every 5 s via new message `GET_TRAFFIC`.
- Burp Jython feeder remains supported and is labeled `source: 'live'`.

## 5. UI additions

New tabs: **Site map** (crawl results + inventory) and **OWASP Top 10** (10 categories, counts, related cards).
Attack surface tab shows form/input locations (selector + XPath) and URL param origins.
Header shows a badge: `AI: on` and `Traffic: live`.
Add **Crawl site** button near Scan.

## Files owned
- Bridge worker: `bridge/**`
- Core worker: `extension/src/core/**`, `extension/test/**`
- UI worker: `extension/panel.*`, `extension/background.js`, `extension/manifest.*.json`
