// The configuration layer and the OpenAPI rules against a fixture. A `# expect: <Category>` or
// `// expect: <Category>` line names the category the next line must carry; `expect-none` says the
// next line carries none. package.json and openapi.yaml are checked by category totals.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { structuralScan } from '../src/fortilike.mjs';
import { openapiScan } from '../src/openapi.mjs';

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), 'structural', 'fixture');

test('configuration rules match the expect lines', () => {
  const findings = structuralScan(FIXTURE, ['node_modules']);
  const have = new Set(findings.map((f) => `${f.category}|${f.path}|${f.line}`));
  const problems = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) { walk(p); continue; }
      if (e.name === 'openapi.yaml' || e.name === 'package.json') continue;
      const rel = relative(FIXTURE, p).split(sep).join('/');
      readFileSync(p, 'utf8').split('\n').forEach((l, i) => {
        const m = /(?:#|\/\/)\s*expect(?::\s*(.+)|-none)\s*$/.exec(l.trim());
        if (!m) return;
        const next = i + 2;
        const onNext = findings.filter((f) => f.path === rel && f.line === next);
        if (m[1] && !have.has(`${m[1].trim()}|${rel}|${next}`)) problems.push(`missing ${m[1].trim()} at ${rel}:${next}`);
        if (!m[1] && onNext.length) problems.push(`unexpected ${onNext.map((f) => f.category).join(', ')} at ${rel}:${next}`);
      });
    }
  };
  walk(FIXTURE);
  if (!findings.some((f) => f.path === 'package.json' && f.category === 'Insecure Transport')) problems.push('missing Insecure Transport in package.json');
  assert.deepEqual(problems, []);
});

test('OpenAPI rules report weak schemes and unauthenticated operations', () => {
  const h = { categoryDefaults: () => ({ kingdom: 'Security Features', impact: 2, probability: 3, accuracy: 4, cwe: [] }), fortifyPriority: () => ['Low', 1], classify: () => 'config', instanceId: (a, b, c) => `${a}${b}${c}` };
  const cats = openapiScan(FIXTURE, ['node_modules'], null, h).map((f) => f.category).sort();
  assert.deepEqual(cats, [
    'OpenAPI Misconfiguration: Empty Operation Security Requirement',
    'OpenAPI Misconfiguration: Missing Error Handling',
    'OpenAPI Misconfiguration: Missing Global Security Requirement',
    'OpenAPI Misconfiguration: Weak Authentication',
  ]);
});
