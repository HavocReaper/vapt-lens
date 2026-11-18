import test from "node:test";
import assert from "node:assert/strict";
import { analyze } from "../bridge/lib/analyze.mjs";
import { parseBurpRaw } from "../bridge/lib/burp.mjs";
import { observePage } from "../extension/src/core/scanner.js";

const minimalKb = {
  generatedAt: "2026-01-01T00:00:00.000Z",
  skills: [
    {
      id: "offensive-xss",
      name: "SKILL: Cross-Site Scripting (XSS)",
      description: "XSS testing checklist",
      triggers: ["XSS", "cross-site scripting"],
      categories: ["xss"],
      sections: [
        {
          heading: "Shortcut",
          bullets: ["Look for user input opportunities on the application."],
          codeBlocks: ["<script>alert(1)</script>"],
        },
      ],
      sourcePath: "offensive-xss/SKILL.md",
    },
  ],
  rules: [
    {
      id: "form-to-xss",
      when: { any: ["signals.hasTextInput"] },
      skillIds: ["offensive-xss"],
      category: "xss",
      priority: 90,
    },
  ],
};

function fakeDoc() {
  const input = {
    name: "search", type: "text", id: "q", placeholder: "Search",
    required: false, maxLength: 100, value: "SUPER_SECRET_VALUE",
  };
  return {
    title: "Test",
    querySelectorAll(selector) {
      if (selector === "form") {
        return [{
          getAttribute: (k) => ({ action: "/search", method: "get" }[k] ?? null),
          querySelectorAll: () => [input],
        }];
      }
      if (selector.includes("input") || selector.includes("textarea")) return [input];
      if (selector === "a[href]") return [{ getAttribute: () => "/api/users" }];
      if (selector === "script") return [{ getAttribute: () => null, textContent: "fetch('/api/v1/items')" }];
      if (selector === "meta[name=generator]") return [];
      return [];
    },
  };
}

test("page observation redacts values and detects form signals", () => {
  const obs = observePage({
    href: "https://example.test/search?q=hello&token=abc123",
    title: "Test",
    doc: fakeDoc(),
    cookies: [{ name: "sessionid", httpOnly: true, secure: true, sameSite: "Lax", value: "TOP_SECRET" }],
    headers: [{ name: "authorization", value: "Bearer SECRET" }, { name: "x-frame-options", value: "DENY" }],
  });

  assert.equal(obs.host, "example.test");
  assert.equal(obs.signals.hasForm, true);
  assert.equal(obs.signals.hasTextInput, true);
  assert.ok(obs.queryParams.some((p) => p.name === "token" && !("value" in p)));
  assert.ok(!JSON.stringify(obs).includes("SUPER_SECRET_VALUE"));
  assert.ok(!JSON.stringify(obs).includes("TOP_SECRET"));
  assert.ok(!JSON.stringify(obs).includes("Bearer SECRET"));
});

test("analysis returns guidance cards with expected shape", async () => {
  const observation = observePage({ href: "https://example.test/", title: "T", doc: fakeDoc() });
  const result = await analyze({
    observation,
    traffic: [],
    options: { ai: false, maxCards: 5, authorized: true },
    kb: minimalKb,
  });

  assert.ok(Array.isArray(result.cards));
  assert.ok(result.cards.length > 0, "expected at least one local card");
  assert.equal(result.aiUsed, false);
  for (const card of result.cards) {
    assert.ok(card.id && card.title && card.category);
    assert.ok(Array.isArray(card.steps) && card.steps.length > 0);
    assert.ok(Array.isArray(card.payloads));
    assert.equal(card.source, "local");
  }
});

test("burp import keeps metadata but drops secret values", () => {
  const raw = `<?xml version="1.0"?>
  <items>
    <item method="GET" url="https://example.test/api/users?id=42" host="example.test" status="200" mimeType="application/json" length="123">
      <parameter name="id" value="42"/>
    </item>
  </items>`;
  const { items } = parseBurpRaw({ source: "burp-xml", raw, host: "example.test" });
  assert.ok(items.length >= 1);
  assert.equal(items[0].method, "GET");
  assert.ok(!JSON.stringify(items).includes('value="42"'));
});
