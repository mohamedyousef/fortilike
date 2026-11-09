import { readFileSync, createReadStream, renameSync } from 'node:fs';
import * as fs from 'node:fs';
import { basename, join } from 'node:path';
import { createServer } from 'node:http';
import https from 'node:https';
import { exec, execSync, spawn } from 'node:child_process';
import * as cp from 'node:child_process';
import vm from 'node:vm';

declare function escapeHtml(text: string): string;
declare function escapeRegExp(text: string): string;
declare const db: { query(...args: unknown[]): unknown };
declare const server: { listen(...args: unknown[]): unknown };
declare function trustedExecutable(path: string): string;
declare function trustedDirectory(path: string): string;
declare function sameOriginUrl(origin: string, raw: string): URL;

createServer((request, response) => {
  const url = new URL(request.url ?? '/', 'http://app.invalid');
  const file = join('/srv', url.pathname);
  // ruleid: fortify.path-manipulation
  readFileSync(file, 'utf8');
  const safe = join('/srv', basename(url.pathname));
  // ok: fortify.path-manipulation
  readFileSync(safe, 'utf8');
  // ok: fortify.path-manipulation
  readFileSync('/etc/hostname', 'utf8');
  const header = request.headers['x-file'] as string;
  // ruleid: fortify.path-manipulation
  createReadStream(header).pipe(response);
  // ruleid: fortify.path-manipulation
  fs.writeFileSync(join('/srv', url.pathname), 'x');
  const target = url.searchParams.get('to') ?? '';
  // ruleid: fortify.path-manipulation
  renameSync('/srv/a', target);

  // ruleid: fortify.command-injection
  exec('convert ' + url.searchParams.get('name'));
  // ruleid: fortify.command-injection
  cp.execSync(`ls ${header}`);
  // ok: fortify.command-injection
  spawn('ls', [header]);
  // ruleid: fortify.command-injection
  spawn('sh', [header], { shell: true });

  // ruleid: fortify.server-side-request-forgery
  fetch(url.searchParams.get('u') ?? '');
  // ruleid: fortify.server-side-request-forgery
  https.get(header, () => {});
  // ok: fortify.server-side-request-forgery
  fetch('https://api.example.com/items?id=' + encodeURIComponent(header));
  // ok: fortify.server-side-request-forgery
  fetch('https://api.example.com/items');
  // ok: fortify.server-side-request-forgery
  fetch(sameOriginUrl('http://127.0.0.1:4200', request.url ?? '/'));

  // ruleid: fortify.open-redirect
  response.setHeader('Location', url.searchParams.get('next') ?? '/');
  // ruleid: fortify.open-redirect
  response.writeHead(302, { Location: header });
  // ok: fortify.open-redirect
  response.setHeader('Location', '/signed-in');

  // ruleid: fortify.header-manipulation
  response.setHeader('x-echo', header);
  // ok: fortify.header-manipulation
  response.setHeader('x-count', String(Number(header)));
  // ok: fortify.header-manipulation
  response.setHeader('content-type', 'text/plain');

  // ruleid: fortify.cross-site-scripting-reflected
  response.end('<h1>' + url.searchParams.get('q') + '</h1>');
  // ok: fortify.cross-site-scripting-reflected
  response.end(escapeHtml(url.searchParams.get('q') ?? ''));
  // ok: fortify.cross-site-scripting-reflected
  response.end(JSON.stringify({ q: url.searchParams.get('q') }));
  // ok: fortify.cross-site-scripting-reflected
  response.end('not found');

  // ruleid: fortify.log-forging
  console.log('request for', request.url);
  // ok: fortify.log-forging
  console.log('request for', JSON.stringify(request.url));
  // ok: fortify.log-forging
  console.log('request handled');

  // ruleid: fortify.denial-of-service-regular-expression
  new RegExp(url.searchParams.get('pattern') ?? '');
  // ok: fortify.denial-of-service-regular-expression
  new RegExp(escapeRegExp(header));

  // ruleid: fortify.dynamic-code-evaluation-code-injection
  eval(header);
  // ruleid: fortify.dynamic-code-evaluation-code-injection
  vm.runInNewContext(url.searchParams.get('code') ?? '', {});
  // ok: fortify.dynamic-code-evaluation-code-injection
  eval('1 + 1');

  // ruleid: fortify.sql-injection
  db.query("SELECT * FROM t WHERE id = '" + url.searchParams.get('id') + "'");
  // ok: fortify.sql-injection
  db.query('SELECT * FROM t WHERE id = $1', [url.searchParams.get('id')]);

  // ruleid: fortify.resource-injection
  server.listen(header);
  // ok: fortify.resource-injection
  server.listen(8788);

  // ruleid: fortify.setting-manipulation
  process.env.HOME = header;
});

const input = process.argv[2] ?? '';
// ruleid: fortify.path-manipulation
readFileSync(input);
// ruleid: fortify.command-injection
execSync('open ' + input);
// ruleid: fortify.command-injection
spawn(process.env.BROWSER ?? 'open', [input]);
// ok: fortify.command-injection
spawn('open', [input]);
// ok: fortify.command-injection
spawn(trustedExecutable(process.env.MINIKIT_DART_CLI ?? 'minikit'), [input]);
// ok: fortify.path-manipulation
readFileSync(trustedDirectory(input) + '/package.json');
