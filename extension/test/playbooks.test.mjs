import test from 'node:test';
import assert from 'node:assert/strict';

import { PLAYBOOKS, findPlaybook, payloadsFor, payloadsForPlaybook } from '../src/core/playbooks.js';

const DANGEROUS = [
  /drop\s+table/i,
  /rm\s+-rf/i,
  /reverse\s+shell/i,
  /nc\s+-e/i,
  /mshta/i,
  /certutil/i,
  /powershell/i,
  /fetch\s*\(/i,
  /mermaid/i,
  /websocket/i,
];

test('playbooks: all required attack classes are present', () => {
  const ids = PLAYBOOKS.map((p) => p.id);
  for (const expected of ['sqli', 'lfi', 'xss', 'cmdi', 'ssti', 'ssrf', 'xxe', 'idor', 'auth', 'upload', 'redirect', 'graphql']) {
    assert.ok(ids.includes(expected), `missing playbook: ${expected}`);
  }
  assert.equal(new Set(ids).size, ids.length, 'playbook ids must be unique');
});

test('playbooks: every entry has guidance, techniques and copyable probes', () => {
  for (const book of PLAYBOOKS) {
    assert.ok(book.title && book.summary && book.owasp && book.verify && book.defense, book.id);
    assert.ok(book.techniques.length >= 2, `${book.id} has too few techniques`);
    assert.ok(book.payloads.length >= 3, `${book.id} has too few payloads`);

    for (const payload of book.payloads) {
      assert.ok(payload.label && payload.value, `${book.id} payload missing label/value`);
      assert.ok(payload.value.length <= 160, `${book.id} payload too long`);
      assert.ok(!/[\r\n]/.test(payload.value), `${book.id} payload is not single-line`);
      for (const pattern of DANGEROUS) {
        assert.ok(!pattern.test(payload.value), `${book.id} payload blocked: ${payload.value}`);
      }
    }
  }
});

test('findPlaybook: resolves categories, skill ids and aliases', () => {
  assert.equal(findPlaybook('sqli')?.id, 'sqli');
  assert.equal(findPlaybook('injection')?.id, 'sqli');
  assert.equal(findPlaybook('xss')?.id, 'xss');
  assert.equal(findPlaybook('path-traversal')?.id, 'lfi');
  assert.equal(findPlaybook('offensive-idor')?.id, 'idor');
  assert.equal(findPlaybook('totally-unknown')?.id ?? '', '');
});

test('payloadsFor: returns a bounded, labelled subset', () => {
  const two = payloadsFor('sqli', '', 2);
  assert.equal(two.length, 2);
  assert.ok(two.every((p) => p.label && p.value));

  const all = payloadsForPlaybook('xss');
  assert.ok(all.some((p) => p.value.includes('<script>')));
  assert.ok(all.length >= 3);
});
