#!/usr/bin/env node
/** End-to-end smoke test: starts the bridge on a spare port and exercises its API. */
import { spawn } from "node:child_process";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(dirname(fileURLToPath(import.meta.url)), "..");
const port = Number(process.env.SMOKE_PORT || 8899);
const base = `http://127.0.0.1:${port}`;

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

async function waitForHealth(timeoutMs = 15000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    try {
      const res = await fetch(`${base}/api/health`);
      if (res.ok) return await res.json();
    } catch {
      /* not up yet */
    }
    await sleep(200);
  }
  throw new Error("bridge did not become healthy in time");
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

const server = spawn(process.execPath, ["bridge/server.mjs"], {
  cwd: root,
  env: { ...process.env, PORT: String(port) },
  stdio: ["ignore", "pipe", "pipe"],
});

let serverLog = "";
server.stdout.on("data", (chunk) => (serverLog += chunk.toString()));
server.stderr.on("data", (chunk) => (serverLog += chunk.toString()));

try {
  const health = await waitForHealth();
  assert(health.ok === true, "health response missing ok:true");
  console.log("health:", health);

  const kbRes = await fetch(`${base}/api/kb?summary=1`);
  const kb = await kbRes.json();
  console.log("kb summary:", kb);

  const observation = {
    capturedAt: new Date().toISOString(),
    url: "https://example.test/search?q=x",
    origin: "https://example.test",
    host: "example.test",
    path: "/search",
    title: "Test",
    queryParams: [{ name: "q", valueLength: 1 }],
    technologies: [],
    headers: [{ name: "x-frame-options", value: "DENY" }],
    cookies: [{ name: "sessionid", httpOnly: true, secure: true, sameSite: "Lax", valueLength: 10 }],
    forms: [{
      action: "/search", method: "GET", enctype: "", hasFileInput: false,
      fields: [{ name: "q", type: "text", id: "q", placeholder: "", required: false, maxLength: 100 }],
    }],
    links: [], scripts: [], endpoints: [], domSinks: [],
    signals: {
      hasForm: true, hasTextInput: true, hasFileInput: false, hasLogin: false,
      hasSearch: true, hasUpload: false, hasGraphql: false, hasApiBase: false,
      hasRedirectParam: false, hasDebugParam: false, hasIdParam: false,
      hasUrlParam: false, hasJsonBodyHint: false, hasJwt: false,
      hasSessionCookie: true, hasCsp: false, hasMissingSecurityHeaders: true,
      hasInlineScript: false, hasDomSink: false, hasCsrfTokenField: false,
    },
    counts: { forms: 1, inputs: 1, links: 0, scripts: 0, endpoints: 0 },
  };

  const analyzeRes = await fetch(`${base}/api/analyze`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      observation,
      traffic: [],
      options: { ai: false, maxCards: 5, authorized: true },
    }),
  });
  const analysis = await analyzeRes.json();
  assert(analyzeRes.ok, `analyze failed: ${JSON.stringify(analysis)}`);
  assert(Array.isArray(analysis.cards), "analysis.cards is not an array");
  console.log(`analyze: ${analysis.cards.length} cards, aiUsed=${analysis.aiUsed}`);

  const importRes = await fetch(`${base}/api/burp/import`, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({
      host: "example.test",
      source: "burp-xml",
      raw: '<?xml version="1.0"?><items><item method="GET" url="https://example.test/api/users?id=1" host="example.test" status="200" mimeType="application/json" length="10"><parameter name="id" value="1"/></item></items>',
    }),
  });
  const imported = await importRes.json();
  assert(importRes.ok && imported.count > 0, `import failed: ${JSON.stringify(imported)}`);
  console.log(`burp import: ${imported.count} items`);

  const trafficRes = await fetch(`${base}/api/burp/traffic?host=example.test`);
  const traffic = await trafficRes.json();
  assert(Array.isArray(traffic.items) && traffic.items.length > 0, "traffic not stored");
  console.log("smoke test passed");
} catch (error) {
  console.error("smoke test failed:", error.message);
  console.error("bridge output:\n" + serverLog);
  process.exitCode = 1;
} finally {
  server.kill("SIGTERM");
}
