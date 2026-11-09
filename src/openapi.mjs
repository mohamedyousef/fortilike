/**
 * OpenAPI Misconfiguration rules (Fortify's JSON/YAML rulepack family) over openapi.yaml / openapi.json
 * documents, plus a YAML loader: the target's own `yaml` or `js-yaml` package when it has one, else a
 * small block-YAML reader that covers the shapes OpenAPI files use.
 */
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, relative, sep, basename } from 'node:path';

export function loadYaml(target, text) {
  const tries = [
    () => { const y = createRequire(join(target, 'package.json'))('yaml'); return y.parse(text); },
    () => { const y = createRequire(join(target, 'package.json'))('js-yaml'); return y.load(text); },
    () => { const y = createRequire(import.meta.url)('yaml'); return y.parse(text); },
  ];
  for (const t of tries) { try { return t(); } catch { /* next */ } }
  return miniYaml(text);
}

/** Block mappings, sequences, quoted and plain scalars, folded/literal blocks, comments. No anchors, no flow collections beyond [] and {}. */
export function miniYaml(text) {
  const lines = text.replace(/\t/g, '  ').split(/\r?\n/);
  const items = [];
  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i];
    if (!raw.trim() || /^\s*#/.test(raw)) continue;
    const indent = raw.match(/^ */)[0].length;
    items.push({ indent, text: raw.trim(), line: i + 1 });
  }
  let pos = 0;
  const scalar = (s) => {
    s = s.replace(/\s+#.*$/, '').trim();
    if (s === '' || s === '~' || s === 'null') return null;
    if (s === 'true') return true;
    if (s === 'false') return false;
    if (/^-?\d+(\.\d+)?$/.test(s)) return Number(s);
    if (/^".*"$/.test(s)) { try { return JSON.parse(s); } catch { return s.slice(1, -1); } }
    if (/^'.*'$/.test(s)) return s.slice(1, -1).replace(/''/g, "'");
    if (s === '[]') return [];
    if (s === '{}') return {};
    if (/^\[.*\]$/.test(s)) return s.slice(1, -1).split(',').map((x) => scalar(x)).filter((x) => x !== null);
    return s;
  };
  const block = (indent) => {
    // literal or folded block: collect lines deeper than indent
    const out = [];
    while (pos < items.length && items[pos].indent > indent) out.push(items[pos++].text);
    return out.join('\n');
  };
  const parse = (indent) => {
    if (pos >= items.length) return null;
    const first = items[pos];
    if (first.text.startsWith('- ') || first.text === '-') {
      const arr = [];
      while (pos < items.length && items[pos].indent === indent && (items[pos].text.startsWith('- ') || items[pos].text === '-')) {
        const it = items[pos];
        const rest = it.text === '-' ? '' : it.text.slice(2);
        if (!rest) { pos++; arr.push(parse(indent + 1 > (items[pos]?.indent ?? 0) ? items[pos]?.indent ?? indent + 2 : items[pos].indent)); continue; }
        if (/^[^'"#\[\]{}]*?:(\s|$)/.test(rest)) {
          // inline mapping starting on the dash line: treat as a mapping whose first key is on this line
          const childIndent = indent + 2;
          items[pos] = { indent: childIndent, text: rest, line: it.line };
          arr.push(parse(childIndent));
          continue;
        }
        pos++;
        arr.push(scalar(rest));
      }
      return arr;
    }
    const obj = {};
    Object.defineProperty(obj, '__lines', { value: {}, enumerable: false });
    while (pos < items.length && items[pos].indent === indent && !items[pos].text.startsWith('- ')) {
      const it = items[pos];
      const m = /^("(?:[^"\\]|\\.)*"|'[^']*'|[^:#]+?)\s*:(?:\s+(.*))?$/.exec(it.text);
      if (!m) { pos++; continue; }
      let key = m[1].trim();
      if (/^["']/.test(key)) key = key.slice(1, -1);
      const val = m[2];
      obj.__lines[key] = it.line;
      pos++;
      if (val === undefined || val === '') {
        if (pos < items.length && items[pos].indent > indent) obj[key] = parse(items[pos].indent);
        else if (pos < items.length && items[pos].indent === indent && items[pos].text.startsWith('- ')) obj[key] = parse(indent);
        else obj[key] = null;
      } else if (val === '|' || val === '>' || /^[|>][-+]?$/.test(val)) obj[key] = block(indent);
      else obj[key] = scalar(val);
    }
    return obj;
  };
  return parse(items[0]?.indent ?? 0);
}

const isOpenApiName = (name) => /(^|[.-])(openapi|swagger|api)(-v?\d+)?\.(ya?ml|json)$/i.test(name) || /^openapi.*\.(ya?ml|json)$/i.test(name);

function lineOf(text, needle, from = 0) {
  const idx = text.indexOf(needle, from);
  if (idx < 0) return 1;
  return text.slice(0, idx).split('\n').length;
}

export function openapiScan(root, excludes, allowed, helpers) {
  const { categoryDefaults, fortifyPriority, classify, instanceId } = helpers;
  const findings = [];
  const files = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist') continue;
      const full = join(dir, e.name);
      const rel = relative(root, full).split(sep).join('/');
      if (excludes.some((g) => rel === g || rel.startsWith(g.replace(/\/+$/, '') + '/') || e.name === g)) continue;
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && isOpenApiName(e.name) && (!allowed || allowed.has(rel))) files.push({ full, rel });
    }
  };
  walk(root);
  for (const { full, rel } of files) {
    let text;
    try { if (statSync(full).size > 5_000_000) continue; text = readFileSync(full, 'utf8'); } catch { continue; }
    let doc;
    try { doc = rel.endsWith('.json') ? JSON.parse(text) : loadYaml(root, text); } catch { continue; }
    if (!doc || typeof doc !== 'object' || !(doc.openapi || doc.swagger)) continue;
    const lines = text.split(/\r?\n/);
    const kind = classify(rel);
    const emit = (id, category, line, message) => {
      const d = categoryDefaults(category);
      const [priority, likelihood] = fortifyPriority(d.impact, d.probability, d.accuracy, 4);
      const snippet = lines.slice(Math.max(0, line - 1), line + 2).join('\n').slice(0, 400);
      findings.push({
        instance_id: instanceId(id, rel, lines[line - 1] ?? snippet), rule: id, category, kingdom: d.kingdom, priority, impact: d.impact,
        likelihood: Math.round(likelihood * 100) / 100, path: rel, line, end_line: line, snippet, message, abstract: '', kind, engine: 'openapi',
        cwe: [...(d.cwe ?? [])], owasp: ['A07:2021 Identification and Authentication Failures'], trace: [], status: 'existing',
      });
    };
    const schemes = doc.components?.securitySchemes ?? doc.securityDefinitions ?? {};
    const schemeNames = Object.keys(schemes);
    if (!schemeNames.length) emit('fortify.openapi-misconfiguration-missing-security-schemes', 'OpenAPI Misconfiguration: Missing Security Schemes', 1, 'The API description defines no security scheme, so no operation can declare how callers authenticate.');
    for (const [name, sch] of Object.entries(schemes)) {
      const schemesAt = Math.max(0, text.search(/^\s*(securitySchemes|securityDefinitions)\s*:/m));
      const line = lineOf(text, `${name}:`, schemesAt) || 1;
      if (!sch || typeof sch !== 'object') continue;
      if (sch.type === 'http' && /^basic$/i.test(sch.scheme ?? '')) emit('fortify.openapi-misconfiguration-weak-authentication', 'OpenAPI Misconfiguration: Weak Authentication', line, `Security scheme "${name}" uses HTTP Basic: credentials travel with every request.`);
      if (sch.type === 'apiKey') {
        if (sch.in !== 'cookie') emit('fortify.openapi-misconfiguration-weak-authentication', 'OpenAPI Misconfiguration: Weak Authentication', line, `Security scheme "${name}" is a static API key in the ${sch.in ?? 'request'}.`);
        if (sch.in === 'query') emit('fortify.openapi-misconfiguration-credential-leakage', 'OpenAPI Misconfiguration: Credential Leakage', line, `Security scheme "${name}" carries the API key in the query string, where logs, proxies and the browser history keep it.`);
      }
      if (sch.type === 'oauth2' && sch.flows && (sch.flows.password || sch.flows.implicit)) emit('fortify.openapi-misconfiguration-weak-authentication', 'OpenAPI Misconfiguration: Weak Authentication', line, `Security scheme "${name}" allows the ${sch.flows.password ? 'password' : 'implicit'} OAuth2 flow.`);
    }
    const globalSec = doc.security;
    const secLine = lineOf(text, '\nsecurity:') + (text.includes('\nsecurity:') ? 1 : 0) || 1;
    const emptyReq = (list) => Array.isArray(list) && list.some((r) => r && typeof r === 'object' && Object.keys(r).length === 0);
    if (globalSec === undefined) emit('fortify.openapi-misconfiguration-missing-global-security-requirement', 'OpenAPI Misconfiguration: Missing Global Security Requirement', 1, 'No top-level security requirement: operations without their own are unauthenticated.');
    else if (Array.isArray(globalSec) && globalSec.length === 0) emit('fortify.openapi-misconfiguration-empty-global-security-requirement', 'OpenAPI Misconfiguration: Empty Global Security Requirement', secLine, 'The top-level security requirement is empty, which declares the API unauthenticated.');
    else if (emptyReq(globalSec) && globalSec.length > 1) emit('fortify.openapi-misconfiguration-optional-global-security-requirement', 'OpenAPI Misconfiguration: Optional Global Security Requirement', secLine, 'The top-level security requirement contains {} as an alternative, so authentication is optional.');
    for (const [path, ops] of Object.entries(doc.paths ?? {})) {
      if (!ops || typeof ops !== 'object') continue;
      const pathLine = lineOf(text, `${path}:`) || lineOf(text, `"${path}"`) || 1;
      for (const [method, op] of Object.entries(ops)) {
        if (!/^(get|post|put|patch|delete|head|options|trace)$/.test(method) || !op || typeof op !== 'object') continue;
        const opLine = lineOf(text, `${method}:`, text.split('\n').slice(0, pathLine).join('\n').length) || pathLine;
        const where = `${method.toUpperCase()} ${path}`;
        if (op.security === undefined) { if (globalSec === undefined) emit('fortify.openapi-misconfiguration-missing-operation-security-requirement', 'OpenAPI Misconfiguration: Missing Operation Security Requirement', opLine, `${where} declares no security requirement and there is no global one.`); }
        else if (Array.isArray(op.security) && op.security.length === 0) emit('fortify.openapi-misconfiguration-empty-operation-security-requirement', 'OpenAPI Misconfiguration: Empty Operation Security Requirement', opLine, `${where} sets security: [] and is unauthenticated.`);
        else if (emptyReq(op.security) && op.security.length > 1) emit('fortify.openapi-misconfiguration-optional-operation-security-requirement', 'OpenAPI Misconfiguration: Optional Operation Security Requirement', opLine, `${where} lists {} as an alternative security requirement, so authentication is optional.`);
        const responses = Object.keys(op.responses ?? {});
        if (responses.length && !responses.some((c) => c === 'default' || /^[45]/.test(c))) emit('fortify.openapi-misconfiguration-missing-error-handling', 'OpenAPI Misconfiguration: Missing Error Handling', opLine, `${where} documents no 4xx, 5xx or default response.`);
      }
    }
    for (const srv of doc.servers ?? []) {
      const url = typeof srv === 'object' ? srv?.url : srv;
      if (typeof url === 'string' && /^http:\/\//i.test(url) && !/^http:\/\/(localhost|127\.|\[::1\])/.test(url)) emit('fortify.openapi-misconfiguration-insecure-transport', 'OpenAPI Misconfiguration: Insecure Transport', lineOf(text, url), `Server ${url} is reached over plain HTTP.`);
    }
    if (doc.swagger && Array.isArray(doc.schemes) && doc.schemes.includes('http')) emit('fortify.openapi-misconfiguration-insecure-transport', 'OpenAPI Misconfiguration: Insecure Transport', lineOf(text, 'schemes'), 'The API allows plain HTTP.');
  }
  return findings;
}

export const _basename = basename;
