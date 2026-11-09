// The global dataflow engine against a fixture: every line under a `// df-ruleid: <Category>`
// comment must carry an issue of that category, every line under `// df-ok: <Category>` must not.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { buildProgram, globalDataflow, loadTypescript } from '../src/dataflow.mjs';

const FIXTURE = join(dirname(fileURLToPath(import.meta.url)), 'dataflow', 'fixture');

function expectations() {
  const want = [];
  const walk = (d) => {
    for (const e of readdirSync(d, { withFileTypes: true })) {
      const p = join(d, e.name);
      if (e.isDirectory()) walk(p);
      else if (/\.(ts|tsx)$/.test(e.name) && !e.name.endsWith('.d.ts')) {
        const lines = readFileSync(p, 'utf8').split('\n');
        lines.forEach((l, i) => {
          const m = /\/\/ df-(ruleid|ok): (.+)$/.exec(l.trim());
          if (m) want.push({ file: relative(FIXTURE, p).split(sep).join('/'), line: i + 2, expect: m[1] === 'ruleid', category: m[2].trim() });
        });
      }
    }
  };
  walk(FIXTURE);
  return want;
}

test('global dataflow finds every df-ruleid and none of the df-ok lines', { skip: !loadTypescript(FIXTURE) && 'typescript is not installed' }, () => {
  const ts = loadTypescript(FIXTURE);
  const { program, rootNames } = buildProgram(ts, FIXTURE, { allowed: null, excluded: () => false });
  const { findings } = globalDataflow({ ts, program, target: FIXTURE, rootNames, classify: () => 'production' });
  const have = new Set(findings.map((f) => `${f.category}|${f.sink.file}|${f.sink.line}`));
  const problems = [];
  for (const w of expectations()) {
    const hit = have.has(`${w.category}|${w.file}|${w.line}`);
    if (w.expect && !hit) problems.push(`missing ${w.category} at ${w.file}:${w.line}`);
    if (!w.expect && hit) problems.push(`unexpected ${w.category} at ${w.file}:${w.line}`);
  }
  assert.deepEqual(problems, [], `\n${problems.join('\n')}\n\nall findings:\n${findings.map((f) => `  ${f.category} ${f.sink.file}:${f.sink.line} <= ${f.source.label} ${f.source.file}:${f.source.line}`).join('\n')}`);
});
