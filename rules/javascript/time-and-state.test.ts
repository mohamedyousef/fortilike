import { existsSync, readFileSync, chmodSync, mkdtempSync, writeFileSync } from 'node:fs';
import * as fs from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

export function narrow(path: string): string {
  // ruleid: fortify.race-condition-file-system-access
  if (existsSync(path)) chmodSync(path, 0o600);
  // ruleid: fortify.race-condition-file-system-access
  const text = existsSync(path) ? readFileSync(path, 'utf8') : '';
  // ok: fortify.race-condition-file-system-access
  const there = existsSync(path);
  return text + there;
}

export function stamp(path: string): string | undefined {
  // ruleid: fortify.race-condition-file-system-access
  if (!fs.existsSync(path)) return undefined;
  const q = 1;
  fs.readFileSync(path, 'utf8');
  return String(q);
}

// ruleid: fortify.insecure-temporary-file
const lock = join(tmpdir(), 'minikit.lock');
// ok: fortify.insecure-temporary-file
const dir = mkdtempSync(join(tmpdir(), 'minikit-'));
// ruleid: fortify.insecure-temporary-file
writeFileSync('/tmp/minikit-state.json', '{}');
// ok: fortify.insecure-temporary-file
const name = 'report.pdf';
