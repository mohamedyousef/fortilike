/**
 * Global dataflow: Fortify-style taint analysis across functions and files on the TypeScript
 * compiler API. A source (request data, the command line, the environment, a database row, an
 * error, a value named like a secret, the page URL, Web Storage, a network response) is followed
 * through assignments, calls, returns, callbacks, class fields and object literals until it reaches
 * a sink; one issue is reported per (sink, source) pair with the whole path, as Fortify does.
 *
 * The analysis is flow-insensitive and field-insensitive on purpose: it over-approximates the way a
 * licensed scan over-approximates, so the number a team sees here is close to the number the
 * security team will see. Summaries are computed for every function (which parameters reach the
 * return value, which reach a sink) and composed through call sites until nothing changes.
 */
import { createRequire } from 'node:module';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve, sep } from 'node:path';
import { createHash } from 'node:crypto';
import * as S from './dataflow-spec.mjs';

const CODE_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);
const MAX_PASSES = 10;
const MAX_STEPS = 14;
const MAX_FLOWS_PER_VALUE = 40;
const MAX_CALLSITES = 60;

export function loadTypescript(target) {
  const tries = [() => createRequire(join(target, 'package.json'))('typescript'), () => createRequire(import.meta.url)('typescript')];
  for (const t of tries) { try { return t(); } catch { /* next */ } }
  return null;
}

function walkFiles(root, excludedFn, out) {
  let entries;
  try { entries = readdirSync(root, { withFileTypes: true }); } catch { return out; }
  for (const e of entries) {
    const full = join(root, e.name);
    const rel = relative(resolve(root, '..'), full);
    if (e.name === 'node_modules' || e.name === '.git' || excludedFn(full, e.name)) continue;
    if (e.isDirectory()) walkFiles(full, excludedFn, out);
    else if (e.isFile() && CODE_EXTS.has(full.slice(full.lastIndexOf('.')).toLowerCase()) && !full.endsWith('.d.ts')) out.push(full);
  }
  return out;
}

/** Builds one Program over every tsconfig project in the tree plus any code file none of them covers. */
export function buildProgram(ts, target, { allowed, excluded }) {
  const configs = [];
  const findConfigs = (d) => {
    let entries;
    try { entries = readdirSync(d, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      if (e.name === 'node_modules' || e.name === '.git' || e.name === 'dist' || e.name === 'build') continue;
      const p = join(d, e.name);
      if (excluded(p, e.name)) continue;
      if (e.isDirectory()) findConfigs(p);
      else if (e.name === 'tsconfig.json') configs.push(p);
    }
  };
  findConfigs(target);
  const files = new Set();
  let options = null;
  for (const c of configs) {
    const cfg = ts.readConfigFile(c, ts.sys.readFile);
    if (cfg.error) continue;
    const parsed = ts.parseJsonConfigFileContent(cfg.config, ts.sys, dirname(c));
    for (const f of parsed.fileNames) files.add(resolve(f));
    if (parsed.fileNames.length && !options) options = parsed.options;
  }
  const loose = walkFiles(target, excluded, []);
  for (const f of loose) files.add(resolve(f));
  const rootNames = [...files].filter((f) => !f.includes(`${sep}node_modules${sep}`) && !excluded(f, f.slice(f.lastIndexOf(sep) + 1)) && (!allowed || allowed.has(f)));
  const opts = {
    ...(options ?? { module: ts.ModuleKind.ESNext, moduleResolution: ts.ModuleResolutionKind.Bundler, target: ts.ScriptTarget.ES2022, jsx: ts.JsxEmit.Preserve, experimentalDecorators: true }),
    allowJs: true, checkJs: false, noEmit: true, skipLibCheck: true, composite: false, incremental: false, declaration: false, declarationMap: false, sourceMap: false,
    tsBuildInfoFile: undefined, rootDir: undefined, outDir: undefined, declarationDir: undefined, noEmitOnError: false, allowImportingTsExtensions: true, noResolve: false,
  };
  if (!opts.jsx) opts.jsx = ts.JsxEmit.Preserve;
  const program = ts.createProgram(rootNames, opts);
  return { program, rootNames: new Set(rootNames), configs };
}

// --- Flows ------------------------------------------------------------------------------------------

class Flow {
  constructor(source, steps = [], cleanFor = null, fields = []) {
    this.source = source; // { id, kind, label, file, line, text, fnId?, index? }
    this.steps = steps;   // [{ file, line, text, role }]
    this.cleanFor = cleanFor; // Set<category> | null
    this.fields = fields; // property path the data sits under inside an object ([] = the value itself)
  }
  get id() { return this.source.id; }
  get key() { return this.fields.length ? `${this.source.id}|${this.fields.join('.')}` : this.source.id; }
  with(step) {
    const steps = this.steps.length >= MAX_STEPS ? [...this.steps.slice(0, 6), ...this.steps.slice(-(MAX_STEPS - 7)), step] : [...this.steps, step];
    return new Flow(this.source, steps, this.cleanFor, this.fields);
  }
  cleaned(cat) { const s = new Set(this.cleanFor ?? []); s.add(cat); return new Flow(this.source, this.steps, s, this.fields); }
  under(field) { return new Flow(this.source, this.steps, this.cleanFor, [field, ...this.fields].slice(0, 4)); }
  /** Reading `.prop`: data under that property comes out, data under another property stays behind. */
  read(prop) {
    if (!this.fields.length) return this;
    if (this.fields[0] === prop) return new Flow(this.source, this.steps, this.cleanFor, this.fields.slice(1));
    return null;
  }
  flat() { return this.fields.length ? new Flow(this.source, this.steps, this.cleanFor, []) : this; }
}

/** A set of flows keyed by source id; union keeps the first (shortest) path per source. */
class Taint {
  constructor() { this.map = new Map(); }
  static of(flow) { const t = new Taint(); t.map.set(flow.id, flow); return t; }
  get size() { return this.map.size; }
  values() { return this.map.values(); }
  add(flow) {
    const k = flow.key;
    if (this.map.has(k)) return false;
    if (this.map.size >= MAX_FLOWS_PER_VALUE) return false;
    this.map.set(k, flow);
    return true;
  }
  under(field) { return this.size ? this.mapped((f) => f.under(field)) : this; }
  read(prop) { return this.size ? this.mapped((f) => f.read(prop)) : this; }
  flat() { return this.size ? this.mapped((f) => f.flat()) : this; }
  addAll(other) { let changed = false; if (!other) return false; for (const f of other.values()) changed = this.add(f) || changed; return changed; }
  mapped(fn) { const t = new Taint(); for (const f of this.values()) { const r = fn(f); if (r) t.add(r); } return t; }
  static union(...sets) { const t = new Taint(); for (const s of sets) if (s) t.addAll(s); return t; }
}
const EMPTY = new Taint();

// --- Engine ------------------------------------------------------------------------------------------

export function globalDataflow({ ts, program, target, rootNames, classify, log = () => {}, includeTests = true }) {
  const checker = program.getTypeChecker();
  const rel = (f) => relative(target, f).split(sep).join('/');
  const store = new Map();       // symbol -> Taint
  const symKind = new Map();     // symbol -> 'request' | 'response' | 'error' | 'logger' | 'none'
  const fnInfo = new Map();      // function node -> info
  const nodeTypeCache = new WeakMap();
  const implementations = new Map(); // interface/abstract class symbol -> [class nodes]
  const fileText = new Map();
  const isBrowserFile = new Map();
  let memo = new Map();          // expression node -> Taint (per pass)
  let changed = false;
  let fnCounter = 0;
  const sinkHits = [];
  let collecting = false;

  const sourceFiles = program.getSourceFiles().filter((sf) => !sf.isDeclarationFile && rootNames.has(resolve(sf.fileName)) && (includeTests || classify(rel(sf.fileName)) !== 'test'));
  log(`  dataflow: ${sourceFiles.length} files in the program`);

  const lineOf = (node) => { const sf = node.getSourceFile(); return sf.getLineAndCharacterOfPosition(node.getStart(sf)).line + 1; };
  const textOf = (node) => {
    const sf = node.getSourceFile();
    let lines = fileText.get(sf.fileName);
    if (!lines) { lines = sf.text.split(/\r?\n/); fileText.set(sf.fileName, lines); }
    const l = lines[lineOf(node) - 1] ?? '';
    const t = l.trim();
    return t.length > 160 ? t.slice(0, 160) + ' …' : t;
  };
  const step = (node, role) => ({ file: rel(node.getSourceFile().fileName), line: lineOf(node), text: textOf(node), role });
  const browser = (sf) => {
    let b = isBrowserFile.get(sf.fileName);
    if (b === undefined) {
      const f = rel(sf.fileName);
      b = /\.(jsx|tsx)$/.test(f) || /(^|\/)(console|web|client|frontend|browser|ui|app|src\/app|public|pages|components)\//.test(f) && !/(^|\/)(api|server|backend)\//.test(f) || (S.BROWSER_HINTS.test(sf.text) && !/from ['"](node:|fastify|express|@nestjs)/.test(sf.text));
      isBrowserFile.set(sf.fileName, b);
    }
    return b;
  };

  const typeStr = (node) => {
    let s = nodeTypeCache.get(node);
    if (s === undefined) {
      try { s = checker.typeToString(checker.getTypeAtLocation(node)); } catch { s = ''; }
      nodeTypeCache.set(node, s);
    }
    return s;
  };
  const symbolOf = (node) => {
    let sym;
    try { sym = checker.getSymbolAtLocation(node); } catch { return undefined; }
    if (sym && (sym.flags & ts.SymbolFlags.Alias)) { try { sym = checker.getAliasedSymbol(sym); } catch { /* keep */ } }
    return sym;
  };
  const getTaint = (sym) => (sym && store.get(sym)) || EMPTY;
  const addTaint = (sym, taint, viaStep) => {
    if (!sym || !taint || !taint.size) return;
    let cur = store.get(sym);
    if (!cur) { cur = new Taint(); store.set(sym, cur); }
    for (const f of taint.values()) if (cur.add(viaStep ? f.with(viaStep) : f)) changed = true;
  };

  const newSource = (node, kind, label, idNode = node) => {
    const sf = idNode.getSourceFile();
    const id = `${kind}@${rel(sf.fileName)}:${lineOf(idNode)}:${idNode.getStart(sf)}`;
    return Taint.of(new Flow({ id, kind, label, file: rel(sf.fileName), line: lineOf(idNode), text: textOf(idNode) }, [step(node, 'source')]));
  };
  /** A private-by-name source, unless the value's type cannot carry private data (boolean, number, enum literal). */
  const privacySource = (node, name, idNode = node) => {
    const t = typeStr(node).trim();
    if (S.NON_PRIVATE_TYPE.test(t)) return EMPTY;
    if (/=>/.test(t) && /^\(/.test(t)) return EMPTY;
    if (t && !/\b(string|any|unknown|Buffer|Uint8Array|ArrayBuffer|KeyObject|CryptoKey|JWK|Secret|Credential|Password|Token)\b/.test(t)) return EMPTY;
    return newSource(node, S.KIND.privacy, `the value named ${name}`, idNode);
  };
  const paramMarker = (info, index, param) => Taint.of(new Flow({ id: `param@${info.id}#${index}`, kind: 'param', fnId: info.id, index, label: 'a parameter', file: rel(param.getSourceFile().fileName), line: lineOf(param), text: textOf(param) }, []));

  // --- Function registry ----------------------------------------------------------------------------
  const isFnLike = (n) => ts.isFunctionDeclaration(n) || ts.isFunctionExpression(n) || ts.isArrowFunction(n) || ts.isMethodDeclaration(n) || ts.isConstructorDeclaration(n) || ts.isGetAccessorDeclaration(n) || ts.isSetAccessorDeclaration(n);
  const enclosingFn = (n) => { let p = n.parent; while (p && !isFnLike(p)) p = p.parent; return p; };

  const decoratorName = (d) => {
    const e = d.expression;
    const callee = ts.isCallExpression(e) ? e.expression : e;
    return ts.isIdentifier(callee) ? callee.text : ts.isPropertyAccessExpression(callee) ? callee.name.text : '';
  };

  function bindPattern(name, taint, viaStep, opts = {}) {
    if (ts.isIdentifier(name)) { const sym = symbolOf(name); if (opts.kind) symKind.set(sym, opts.kind); addTaint(sym, taint, viaStep); return; }
    if (ts.isObjectBindingPattern(name)) {
      for (const el of name.elements) {
        const prop = el.propertyName ? el.propertyName.getText() : ts.isIdentifier(el.name) ? el.name.text : '';
        let t = el.dotDotDotToken ? taint : taint.read(prop);
        if (opts.fromRequest && S.REQUEST_PROPS.has(prop)) t = Taint.union(taint, newSource(el, S.KIND.web, `request ${prop}`));
        else if (opts.fromRequest && prop === 'raw') { bindPattern(el.name, EMPTY, viaStep, { kind: 'request' }); continue; }
        if (S.PRIVACY_NAME.test(prop)) t = Taint.union(t, privacySource(el, prop));
        bindPattern(el.name, t, viaStep);
      }
      return;
    }
    if (ts.isArrayBindingPattern(name)) for (const el of name.elements) if (!ts.isOmittedExpression(el)) bindPattern(el.name, taint, viaStep);
  }

  function ensureFn(node) {
    let info = fnInfo.get(node);
    if (info) return info;
    info = { id: ++fnCounter, node, params: node.parameters, returnTaint: new Taint(), callSites: [], browser: browser(node.getSourceFile()) };
    fnInfo.set(node, info);
    node.parameters.forEach((p, i) => {
      const decorators = ts.canHaveDecorators?.(p) ? ts.getDecorators(p) ?? [] : [];
      let bound = false;
      for (const d of decorators) {
        const what = S.NEST_PARAM_DECORATORS[decoratorName(d)];
        if (!what) continue;
        bound = true;
        if (what === 'request') bindPattern(p.name, EMPTY, null, { kind: 'request' });
        else if (what === 'response') bindPattern(p.name, EMPTY, null, { kind: 'response' });
        else if (what === 'value') bindPattern(p.name, newSource(p, S.KIND.web, `@${decoratorName(d)}()`), null, { fromRequest: false });
      }
      if (bound) return;
      const t = typeStr(p);
      const pname = ts.isIdentifier(p.name) ? p.name.text : '';
      if (S.REQUEST_TYPES.test(t)) { bindPattern(p.name, EMPTY, null, { kind: 'request', fromRequest: true }); return; }
      if (S.RESPONSE_TYPES.test(t)) { bindPattern(p.name, EMPTY, null, { kind: 'response' }); return; }
      if (S.ERROR_TYPES.test(t) && !/^(unknown|any)$/.test(t)) { bindPattern(p.name, EMPTY, null, { kind: 'error' }); return; }
      if (!info.browser && /^(req|request|httpRequest)$/.test(pname) && /^(any|unknown|)$/.test(t.replace(/<.*/, ''))) { bindPattern(p.name, EMPTY, null, { kind: 'request', fromRequest: true }); return; }
      if (!info.browser && /^(res|reply|response)$/.test(pname) && /^(any|unknown|)$/.test(t.replace(/<.*/, ''))) { bindPattern(p.name, EMPTY, null, { kind: 'response' }); return; }
      if (ts.isObjectBindingPattern(p.name) && S.REQUEST_TYPES.test(t)) { bindPattern(p.name, EMPTY, null, { fromRequest: true }); return; }
      bindPattern(p.name, paramMarker(info, i, p), null);
    });
    return info;
  }

  function registerImplementations(sf) {
    const visit = (n) => {
      if (ts.isClassDeclaration(n) || ts.isClassExpression(n)) {
        for (const h of n.heritageClauses ?? []) for (const t of h.types) {
          const sym = symbolOf(t.expression);
          if (!sym) continue;
          const list = implementations.get(sym) ?? [];
          list.push(n);
          implementations.set(sym, list);
        }
      }
      ts.forEachChild(n, visit);
    };
    visit(sf);
  }

  /** Function nodes a call can reach: the resolved declaration, or every implementation of an interface/abstract method. */
  function calleesOf(call) {
    let sig;
    try { sig = checker.getResolvedSignature(call); } catch { return []; }
    const decl = sig?.declaration;
    const out = [];
    const push = (d) => { if (d && isFnLike(d) && d.body && rootNames.has(resolve(d.getSourceFile().fileName))) out.push(d); };
    if (!decl) {
      // Overload-less resolution failed: fall back to the symbol of the callee.
      const sym = symbolOf(ts.isPropertyAccessExpression(call.expression) ? call.expression.name : call.expression);
      for (const d of sym?.declarations ?? []) { if (ts.isVariableDeclaration(d) && d.initializer && isFnLike(d.initializer)) push(d.initializer); else push(d); }
      return out;
    }
    if (ts.isVariableDeclaration(decl) && decl.initializer && isFnLike(decl.initializer)) push(decl.initializer);
    else if (decl.body) push(decl);
    else if (ts.isMethodSignature(decl) || ts.isMethodDeclaration(decl) || ts.isPropertySignature(decl)) {
      const owner = decl.parent;
      const ownerSym = owner.name ? symbolOf(owner.name) : undefined;
      const name = decl.name?.getText();
      const impls = implementations.get(ownerSym) ?? [];
      for (const cls of impls.slice(0, 12)) {
        const m = cls.members.find((mm) => (ts.isMethodDeclaration(mm) || ts.isPropertyDeclaration(mm)) && mm.name?.getText() === name);
        if (m && ts.isMethodDeclaration(m)) push(m);
        else if (m && ts.isPropertyDeclaration(m) && m.initializer && isFnLike(m.initializer)) push(m.initializer);
      }
      if (ts.isPropertySignature(decl) && !impls.length) {
        // A function-typed property on an object literal: find the initializer through the call's expression symbol.
        const sym = symbolOf(ts.isPropertyAccessExpression(call.expression) ? call.expression.name : call.expression);
        for (const d of sym?.declarations ?? []) if (ts.isPropertyAssignment(d) && isFnLike(d.initializer)) push(d.initializer);
      }
    } else if (ts.isConstructorDeclaration(decl) && decl.body) push(decl);
    return out;
  }

  function fnOfIdentifier(expr) {
    if (isFnLike(expr)) return expr;
    if (ts.isIdentifier(expr) || ts.isPropertyAccessExpression(expr)) {
      const sym = symbolOf(ts.isPropertyAccessExpression(expr) ? expr.name : expr);
      for (const d of sym?.declarations ?? []) {
        if (isFnLike(d) && d.body) return d;
        if ((ts.isVariableDeclaration(d) || ts.isPropertyDeclaration(d) || ts.isPropertyAssignment(d)) && d.initializer && isFnLike(d.initializer)) return d.initializer;
      }
    }
    return null;
  }

  // --- Classification of receivers ---------------------------------------------------------------
  const rootIdentifier = (e) => { while (ts.isPropertyAccessExpression(e) || ts.isElementAccessExpression(e) || ts.isNonNullExpression(e) || ts.isParenthesizedExpression(e) || ts.isAsExpression(e) || ts.isCallExpression(e)) e = e.expression; return e; };
  const kindOfSymbol = (sym) => symKind.get(sym) ?? 'none';
  function isRequest(e) {
    if (!e) return false;
    if (ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e)) return isRequest(e.expression);
    if (ts.isIdentifier(e) && kindOfSymbol(symbolOf(e)) === 'request') return true;
    if (ts.isPropertyAccessExpression(e) && (e.name.text === 'raw' || e.name.text === 'request' || e.name.text === 'req') && isRequest(e.expression)) return true;
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression) && /^(getRequest|switchToHttp|getRequest<.*>)$/.test(e.expression.name.text)) return true;
    const t = typeStr(e);
    return S.REQUEST_TYPES.test(t);
  }
  function isResponse(e) {
    if (!e) return false;
    if (ts.isParenthesizedExpression(e) || ts.isNonNullExpression(e) || ts.isAsExpression(e) || ts.isAwaitExpression(e)) return isResponse(e.expression);
    if (ts.isIdentifier(e) && kindOfSymbol(symbolOf(e)) === 'response') return true;
    if (ts.isPropertyAccessExpression(e) && e.name.text === 'raw' && isResponse(e.expression)) return true;
    if (ts.isCallExpression(e) && ts.isPropertyAccessExpression(e.expression)) {
      if (/^(getResponse|getReply)$/.test(e.expression.name.text)) return true;
      if (/^(status|code|header|headers|type|set|append|vary|cookie|setCookie|clearCookie|writeHead|setHeader|hijack|serializer|compress)$/.test(e.expression.name.text) && isResponse(e.expression.expression)) return true;
    }
    const t = typeStr(e);
    if (S.RESPONSE_TYPES.test(t)) return true;
    const root = rootIdentifier(e);
    return ts.isIdentifier(root) && S.RESPONSE_NAMES.test(root.text) && !browser(e.getSourceFile()) && /^(any|unknown|)$/.test(typeStr(root).replace(/<.*/, ''));
  }
  function isLogger(e) {
    if (!e) return false;
    const text = e.getText().replace(/\s+/g, '');
    if (/(^|\.)(console|log|logger|logging)$/.test(text) || /^this\.(log|logger)$/.test(text) || /\.log\.child\(.*\)$/.test(text)) return true;
    if (ts.isIdentifier(e) && S.LOGGER_NAMES.test(e.text) && e.text !== 'debug' && e.text !== 'error' && e.text !== 'warn' && e.text !== 'info' && e.text !== 'trace' && e.text !== 'fatal') return true;
    const t = typeStr(e);
    return S.LOGGER_TYPES.test(t) && !/Response|Request/.test(t);
  }
  function isErrorish(e) {
    if (ts.isIdentifier(e)) {
      const sym = symbolOf(e);
      if (kindOfSymbol(sym) === 'error') return true;
    }
    const t = typeStr(e);
    return S.ERROR_TYPES.test(t) && !/^(unknown|any)$/.test(t);
  }

  /** The npm module (or Node built-in) an identifier was imported from, when it was. */
  function moduleOf(expr) {
    const root = rootIdentifier(expr);
    if (!ts.isIdentifier(root)) return '';
    let sym;
    try { sym = checker.getSymbolAtLocation(root); } catch { return ''; }
    for (const d of sym?.declarations ?? []) {
      if (ts.isImportSpecifier(d) || ts.isImportClause(d) || ts.isNamespaceImport(d)) {
        const decl = ts.isImportSpecifier(d) ? d.parent.parent.parent : ts.isImportClause(d) ? d.parent : d.parent.parent;
        return decl.moduleSpecifier?.text ?? '';
      }
      if (ts.isImportEqualsDeclaration(d) && ts.isExternalModuleReference(d.moduleReference)) return d.moduleReference.expression.getText().replace(/['"]/g, '');
      if (ts.isVariableDeclaration(d) && d.initializer) {
        let init = d.initializer;
        if (ts.isAwaitExpression(init)) init = init.expression;
        if (ts.isPropertyAccessExpression(init)) init = init.expression;
        if (ts.isCallExpression(init) && ts.isIdentifier(init.expression) && init.expression.text === 'require' && init.arguments[0] && ts.isStringLiteral(init.arguments[0])) return init.arguments[0].text;
      }
      if (ts.isBindingElement(d)) {
        const decl = d.parent.parent;
        if (ts.isVariableDeclaration(decl) && decl.initializer && ts.isCallExpression(decl.initializer) && ts.isIdentifier(decl.initializer.expression) && decl.initializer.expression.text === 'require' && ts.isStringLiteral(decl.initializer.arguments[0])) return decl.initializer.arguments[0].text;
      }
    }
    const aliased = symbolOf(root);
    for (const d of aliased?.declarations ?? []) {
      const f = d.getSourceFile().fileName;
      const m = /node_modules\/(@types\/node\/([\w.-]+)|(@[\w.-]+\/[\w.-]+)|([\w.-]+))/.exec(f);
      if (m) return m[2] ?? m[3] ?? m[4] ?? '';
    }
    return '';
  }

  // --- Expression taint ---------------------------------------------------------------------------
  const calleeName = (call) => {
    const e = call.expression;
    if (ts.isIdentifier(e)) {
      let sym;
      try { sym = checker.getSymbolAtLocation(e); } catch { /* none */ }
      const spec = sym?.declarations?.find((d) => ts.isImportSpecifier(d));
      return spec ? (spec.propertyName ?? spec.name).text : e.text;
    }
    if (ts.isPropertyAccessExpression(e)) return e.name.text;
    if (ts.isElementAccessExpression(e) && ts.isStringLiteral(e.argumentExpression)) return e.argumentExpression.text;
    return '';
  };
  const stringish = (node) => {
    if (ts.isStringLiteralLike(node) || ts.isTemplateExpression(node) || (ts.isBinaryExpression(node) && node.operatorToken.kind === ts.SyntaxKind.PlusToken)) return true;
    const t = typeStr(node);
    return /^(string|`|"|')/.test(t) || /\bstring\b/.test(t);
  };
  const numberish = (node) => /^number\b/.test(typeStr(node)) || ts.isNumericLiteral(node);
  const objectish = (node) => { const t = typeStr(node); return !/^(string|number|boolean|`|"|')/.test(t) && !ts.isStringLiteralLike(node); };

  function substitute(returnTaint, call, argTaints, callee) {
    const out = new Taint();
    const callStep = step(call, 'call');
    const info = fnInfo.get(callee);
    for (const f of returnTaint.values()) {
      if (f.source.kind === 'param') {
        if (!info || f.source.fnId !== info.id) continue;
        const idx = f.source.index;
        const restIndex = callee.parameters.findIndex((p) => p.dotDotDotToken);
        const incoming = restIndex >= 0 && idx === restIndex ? Taint.union(...argTaints.slice(idx)) : argTaints[idx];
        if (!incoming) continue;
        for (const g of incoming.values()) {
          const steps = [...g.steps, callStep, ...f.steps, step(call, 'return')];
          out.add(new Flow(g.source, steps.length > MAX_STEPS ? [...steps.slice(0, 6), ...steps.slice(-(MAX_STEPS - 6))] : steps, g.cleanFor, [...f.fields, ...g.fields].slice(0, 4)));
        }
      } else out.add(f.with(step(call, 'return')));
    }
    return out;
  }

  function sanitizerFor(nameText) {
    if (!nameText) return null;
    const last = nameText.split('.').pop();
    if (S.SANITIZERS.all.test(last) || (/^(DOMPurify|z|crypto\.subtle|bcrypt|argon2|validator|he)\./.test(nameText) && S.SANITIZERS.all.test(nameText))) return 'all';
    if (S.SANITIZERS.nameFragments.test(last)) return 'all';
    const cats = [];
    for (const [cat, re] of Object.entries(S.SANITIZERS.byCategory)) if (re.test(last) || re.test(nameText)) cats.push(cat);
    return cats.length ? cats : null;
  }

  function taintOf(node) {
    if (!node) return EMPTY;
    const m = memo.get(node);
    if (m) return m;
    memo.set(node, EMPTY);
    const t = computeTaint(node);
    memo.set(node, t);
    return t;
  }

  function computeTaint(node) {
    const K = ts.SyntaxKind;
    switch (node.kind) {
      case K.Identifier: {
        if (node.text === 'undefined') return EMPTY;
        const sym = symbolOf(node);
        let t = getTaint(sym);
        if (sym && kindOfSymbol(sym) === 'error') t = Taint.union(t, errorSource(sym, node));
        if (S.PRIVACY_NAME.test(node.text) && !/^(Password|Secret|Token|Credential)[A-Z]/.test(node.text) && !(sym && (sym.flags & (ts.SymbolFlags.Function | ts.SymbolFlags.Class | ts.SymbolFlags.Interface | ts.SymbolFlags.TypeAlias | ts.SymbolFlags.Enum | ts.SymbolFlags.Module | ts.SymbolFlags.Method)))) {
          const decl = sym?.declarations?.[0];
          t = Taint.union(t, privacySource(node, node.text, decl && rootNames.has(resolve(decl.getSourceFile().fileName)) ? decl : node));
        }
        return t;
      }
      case K.ThisKeyword: return EMPTY;
      case K.PropertyAccessExpression: {
        const objText = node.expression.getText().replace(/\s+/g, '');
        const prop = node.name.text;
        const sf = node.getSourceFile();
        for (const ps of S.PROPERTY_SOURCES) if ((!ps.browser || browser(sf)) && ps.object.test(objText) && ps.prop.test(prop)) return newSource(node, ps.kind, ps.label);
        if (isRequest(node.expression)) {
          if (S.REQUEST_PROPS.has(prop)) return newSource(node, S.KIND.web, `request ${prop}`);
          return EMPTY;
        }
        if (/^(window\.)?(location)$/.test(objText) && browser(sf)) return newSource(node, S.KIND.dom, "the page's URL");
        let t = taintOf(node.expression).read(prop);
        if (S.CLEAN_PROPS.has(prop)) t = EMPTY;
        if (node.expression.kind === K.ThisKeyword) t = Taint.union(t, getTaint(symbolOf(node.name)));
        if (S.ERROR_PROPS.has(prop) && isErrorish(node.expression) && ![...t.values()].some((f) => f.source.kind === S.KIND.error)) t = Taint.union(t, newSource(node, S.KIND.error, `error.${prop}`));
        if (S.PRIVACY_NAME.test(prop)) t = Taint.union(t, privacySource(node, prop));
        return t;
      }
      case K.ElementAccessExpression: {
        const objText = node.expression.getText().replace(/\s+/g, '');
        if (/^process\.env$/.test(objText)) return newSource(node, S.KIND.env, 'the environment');
        if (/^process\.argv$/.test(objText)) return newSource(node, S.KIND.argv, 'the command line');
        if (isRequest(node.expression)) {
          const key = ts.isStringLiteralLike(node.argumentExpression) ? node.argumentExpression.text : '';
          return key && S.REQUEST_PROPS.has(key) ? newSource(node, S.KIND.web, `request ${key}`) : EMPTY;
        }
        taintOf(node.argumentExpression);
        const keyArg = node.argumentExpression;
        let t = ts.isStringLiteralLike(keyArg) ? taintOf(node.expression).read(keyArg.text) : numberish(keyArg) ? taintOf(node.expression) : taintOf(node.expression).flat();
        if (ts.isStringLiteralLike(node.argumentExpression) && S.PRIVACY_NAME.test(node.argumentExpression.text)) t = Taint.union(t, privacySource(node, node.argumentExpression.text));
        return t;
      }
      case K.CallExpression: return callTaint(node, false);
      case K.NewExpression: return callTaint(node, true);
      case K.TaggedTemplateExpression: {
        const parts = ts.isTemplateExpression(node.template) ? node.template.templateSpans.map((s) => taintOf(s.expression)) : [];
        return Taint.union(...parts);
      }
      case K.TemplateExpression: return Taint.union(...node.templateSpans.map((s) => taintOf(s.expression)));
      case K.BinaryExpression: {
        const op = node.operatorToken.kind;
        if (op === K.EqualsToken || op === K.PlusEqualsToken || op === K.BarBarEqualsToken || op === K.QuestionQuestionEqualsToken || op === K.AmpersandAmpersandEqualsToken) { assignment(node); return taintOf(node.right); }
        if (op === K.CommaToken) { taintOf(node.left); return taintOf(node.right); }
        if (op === K.EqualsEqualsEqualsToken || op === K.ExclamationEqualsEqualsToken || op === K.EqualsEqualsToken || op === K.ExclamationEqualsToken || op === K.LessThanToken || op === K.GreaterThanToken || op === K.LessThanEqualsToken || op === K.GreaterThanEqualsToken || op === K.InstanceOfKeyword || op === K.InKeyword) { taintOf(node.left); taintOf(node.right); return EMPTY; }
        return Taint.union(taintOf(node.left), taintOf(node.right));
      }
      case K.ConditionalExpression: taintOf(node.condition); return Taint.union(taintOf(node.whenTrue), taintOf(node.whenFalse));
      case K.ParenthesizedExpression: case K.AsExpression: case K.NonNullExpression: case K.SatisfiesExpression: case K.TypeAssertionExpression: case K.AwaitExpression: case K.SpreadElement: case K.SpreadAssignment: case K.ExpressionWithTypeArguments: case K.PartiallyEmittedExpression:
        return taintOf(node.expression);
      case K.PrefixUnaryExpression: case K.PostfixUnaryExpression: taintOf(node.operand); return EMPTY;
      case K.TypeOfExpression: case K.VoidExpression: case K.DeleteExpression: taintOf(node.expression); return EMPTY;
      case K.ObjectLiteralExpression: {
        const parts = [];
        for (const p of node.properties) {
          if (ts.isPropertyAssignment(p)) {
            const t = taintOf(p.initializer);
            const key = ts.isIdentifier(p.name) || ts.isStringLiteralLike(p.name) ? p.name.text : '';
            parts.push(key ? t.under(key) : t);
            if (key && S.PRIVACY_NAME.test(key) && t.size === 0 && !ts.isObjectLiteralExpression(p.initializer) && !ts.isArrowFunction(p.initializer) && !ts.isFunctionExpression(p.initializer) && !ts.isStringLiteralLike(p.initializer)) parts.push(privacySource(p.initializer, key, p).under(key));
            if (p.name && ts.isComputedPropertyName(p.name)) { const kt = taintOf(p.name.expression); if (kt.size && collecting) recordHit(sinkById('prototype-pollution-key'), p, kt, p.name.expression); }
          } else if (ts.isShorthandPropertyAssignment(p)) {
            let sym;
            try { sym = checker.getShorthandAssignmentValueSymbol(p); } catch { /* none */ }
            if (sym && (sym.flags & ts.SymbolFlags.Alias)) { try { sym = checker.getAliasedSymbol(sym); } catch { /* keep */ } }
            const key = p.name.text;
            parts.push(getTaint(sym).under(key));
            if (sym && kindOfSymbol(sym) === 'error') parts.push(errorSource(sym, p).under(key));
            if (S.PRIVACY_NAME.test(key)) parts.push(privacySource(p.name, key, p).under(key));
          } else if (ts.isSpreadAssignment(p)) parts.push(taintOf(p.expression));
          else if (ts.isMethodDeclaration(p) || ts.isGetAccessorDeclaration(p) || ts.isSetAccessorDeclaration(p)) visitFunction(p);
        }
        return Taint.union(...parts);
      }
      case K.ArrayLiteralExpression: return Taint.union(...node.elements.map(taintOf));
      case K.ArrowFunction: case K.FunctionExpression: visitFunction(node); return EMPTY;
      case K.ClassExpression: visitNode(node); return EMPTY;
      case K.JsxElement: case K.JsxSelfClosingElement: case K.JsxFragment: case K.JsxExpression: visitNode(node); return EMPTY;
      case K.YieldExpression: return node.expression ? taintOf(node.expression) : EMPTY;
      case K.OmittedExpression: case K.NullKeyword: case K.TrueKeyword: case K.FalseKeyword: case K.NumericLiteral: case K.BigIntLiteral: case K.RegularExpressionLiteral: case K.NoSubstitutionTemplateLiteral: case K.StringLiteral: case K.SuperKeyword:
        return EMPTY;
      default:
        ts.forEachChild(node, (c) => { if (isExpression(c)) taintOf(c); else visitNode(c); });
        return EMPTY;
    }
  }
  const isExpression = (n) => ts.isExpression(n) || ts.isSpreadAssignment?.(n);

  function errorSource(sym, node) {
    const decl = sym.declarations?.[0] ?? node;
    return newSource(node, S.KIND.error, 'a caught error', decl);
  }

  function argumentTaints(call) {
    return (call.arguments ?? []).map((a) => taintOf(a));
  }

  function callTaint(call, isNew) {
    const callee = call.expression;
    const name = calleeName(call);
    const sf = call.getSourceFile();
    const receiver = ts.isPropertyAccessExpression(callee) || ts.isElementAccessExpression(callee) ? callee.expression : null;
    const receiverText = receiver ? receiver.getText().replace(/\s+/g, '') : '';
    const inBrowser = browser(sf);

    // Callbacks: bind their parameters before evaluating anything else.
    bindCallbacks(call, name, receiver);

    const argTaints = argumentTaints(call);
    const receiverTaint = receiver ? taintOf(receiver) : EMPTY;
    if (collecting) checkSinks(call, isNew, name, receiver, receiverText, argTaints, receiverTaint);

    // Sources produced by the call itself.
    if (receiver && isRequest(receiver) && S.REQUEST_METHODS.has(name)) return newSource(call, S.KIND.web, `request.${name}()`);
    for (const cs of S.CALL_PROPERTY_SOURCES) if ((!cs.browser || inBrowser) && receiver && cs.object.test(receiverText) && cs.method.test(name)) return newSource(call, cs.kind, cs.label);
    for (const cs of S.CALL_SOURCES) {
      if (cs.browser && !inBrowser) continue;
      if (!cs.match.test(name)) continue;
      if (cs.receiverType && !(receiver && cs.receiverType.test(typeStr(receiver)))) continue;
      if (cs.receiverName && !(receiver && cs.receiverName.test(receiverText))) continue;
      if (cs.kind === S.KIND.file && !/^(node:)?fs(\/promises)?$|^fs-extra$|^$/.test(moduleOf(callee))) continue;
      if (cs.kind === S.KIND.file && !moduleOf(callee)) continue;
      return newSource(call, cs.kind, cs.label);
    }

    // Sanitizers clean the result.
    const fullName = callee.getText().replace(/\s+/g, '');
    const san = sanitizerFor(fullName);
    if (san === 'all') return EMPTY;

    // Project functions: compose their summaries.
    const callees = calleesOf(call);
    let result = new Taint();
    if (callees.length) {
      for (const fn of callees) {
        const info = ensureFn(fn);
        if (info.callSites.length < MAX_CALLSITES && !info.callSites.some((c) => c.call === call)) info.callSites.push({ call, argTaints, receiverTaint, enclosing: enclosingFn(call) });
        else { const c = info.callSites.find((c) => c.call === call); if (c) { c.argTaints = argTaints; c.receiverTaint = receiverTaint; } }
        result.addAll(substitute(info.returnTaint, call, argTaints, fn));
        if (isNew || ts.isConstructorDeclaration(fn)) result.addAll(Taint.union(...argTaints));
      }
    } else {
      // External code: the result carries whatever went in (strings, buffers, URLs, promises...).
      if (S.CLEAN_METHODS.has(name) && receiver) { return EMPTY; }
      result = Taint.union(receiverTaint, ...argTaints);
      if (/^(then|catch|finally)$/.test(name)) {
        for (const a of call.arguments) { const fn = fnOfIdentifier(a); if (fn) result.addAll(ensureFn(fn).returnTaint); }
      }
      if (/^(map|flatMap|filter|reduce|reduceRight|sort|toSorted|slice|concat|reverse|find|findLast|flat|at|pop|shift|values|entries|keys|from|of|all|allSettled|race|any|resolve)$/.test(name)) {
        for (const a of call.arguments) { const fn = fnOfIdentifier(a); if (fn) result.addAll(ensureFn(fn).returnTaint.mapped((f) => f.source.kind === 'param' ? null : f)); }
      }
    }
    if (Array.isArray(san)) result = result.mapped((f) => san.reduce((acc, c) => acc.cleaned(c), f));
    return result;
  }

  /** Bind callback parameters: array/promise methods pass the receiver's data, routes pass (request, response), events pass their payload. */
  function bindCallbacks(call, name, receiver) {
    const fnArgs = call.arguments.map((a) => fnOfIdentifier(a)).map((fn, i) => fn ? { fn, i } : null).filter(Boolean);
    if (!fnArgs.length) return;
    const receiverText = receiver ? receiver.getText().replace(/\s+/g, '') : '';
    const recvTaint = receiver ? taintOf(receiver) : EMPTY;
    for (const { fn, i } of fnArgs) {
      const info = ensureFn(fn);
      const params = fn.parameters;
      const bind = (idx, taint, kind) => { const p = params[idx]; if (!p) return; bindPattern(p.name, taint, taint.size ? step(call, 'call') : null, kind ? { kind, fromRequest: kind === 'request' } : {}); };
      if (/^(map|forEach|filter|find|findIndex|findLast|findLastIndex|flatMap|some|every|sort|toSorted|reduce|reduceRight)$/.test(name) && receiver) {
        if (/^reduce/.test(name)) { bind(1, recvTaint); if (i === 0 && call.arguments[1]) bind(0, Taint.union(taintOf(call.arguments[1]), recvTaint)); }
        else bind(0, recvTaint);
        if (name === 'sort' || name === 'toSorted') bind(1, recvTaint);
      } else if (/^(then|finally)$/.test(name) && receiver) {
        if (i === 0) bind(0, recvTaint); else bind(0, EMPTY, 'error');
      } else if (name === 'catch' && receiver) {
        bind(0, EMPTY, 'error');
      } else if (/^(on|once|addListener|prependListener|addEventListener|handle|subscribe)$/.test(name) && call.arguments[0] && ts.isStringLiteralLike(call.arguments[0])) {
        const ev = call.arguments[0].text;
        if (ev === 'request' || ev === 'checkContinue' || ev === 'upgrade' || ev === 'connect') { bind(0, EMPTY, 'request'); bind(1, EMPTY, 'response'); }
        else if (ev === 'message') bind(0, newSource(call, browser(call.getSourceFile()) ? S.KIND.dom : S.KIND.web, 'a posted message'));
        else if (ev === 'data' || ev === 'end' || ev === 'readable') bind(0, Taint.union(recvTaint, isRequest(receiver) ? newSource(call, S.KIND.web, 'the request body') : EMPTY));
        else if (ev === 'error') bind(0, EMPTY, 'error');
        else if (/^(input|change|submit|keyup|keydown|paste|drop|hashchange|popstate)$/.test(ev)) bind(0, newSource(call, S.KIND.dom, 'a DOM event'));
        else bind(0, recvTaint);
      } else if ((S.ROUTE_METHODS.has(name) && (!receiver || S.ROUTE_RECEIVERS.test(receiverText) || /Fastify|Express|Router|Application|Server|Hono|Koa/.test(typeStr(receiver)))) || (!receiver && /^(createServer|createSecureServer)$/.test(name))) {
        bind(0, EMPTY, 'request'); bind(1, EMPTY, 'response');
      } else if (/^(setErrorHandler|onError|errorHandler|useErrorHandler)$/.test(name)) {
        bind(0, EMPTY, 'error'); bind(1, EMPTY, 'request'); bind(2, EMPTY, 'response');
      } else if (/^(addHook|register|decorateRequest|decorateReply|preHandler|onRequest|preValidation|preSerialization|onSend|onResponse|onError)$/.test(name)) {
        if (name === 'onError') { bind(0, EMPTY, 'request'); bind(1, EMPTY, 'response'); bind(2, EMPTY, 'error'); }
        else if (!(name === 'register')) { bind(0, EMPTY, 'request'); bind(1, EMPTY, 'response'); }
      } else if (/^(route)$/.test(name)) {
        // fastify.route({ handler }) is an object; nothing to bind here.
      } else {
        // Unknown higher-order function: callback parameters keep their own markers; a known
        // tainted receiver still flows (e.g. stream.pipe(transform)).
        if (recvTaint.size && /^(pipe|pipeline|transform|each|eachSeries|waterfall)$/.test(name)) bind(0, recvTaint);
      }
      visitFunction(fn);
    }
  }

  // --- Sinks --------------------------------------------------------------------------------------
  const sinkIndex = new Map(S.SINKS.map((s) => [s.id, s]));
  const sinkById = (id) => sinkIndex.get(id);

  function recordHit(spec, node, taint, keyNode = null, argIndex = -1, extra = {}) {
    if (!spec || !taint || !taint.size) return;
    sinkHits.push({ spec, node, taint, keyNode, argIndex, fn: enclosingFn(node), ...extra });
  }

  // --- Cross-Session Contamination: a request handler writes state shared by every request ----------
  const ROUTE_DECORATORS = /^(Get|Post|Put|Patch|Delete|All|Head|Options|Search|MessagePattern|EventPattern|SubscribeMessage|Sse)$/;
  const handlerMemo = new Map();
  function isHandler(fn) {
    if (!fn) return false;
    let h = handlerMemo.get(fn);
    if (h !== undefined) return h;
    h = false;
    const decorators = ts.canHaveDecorators?.(fn) ? ts.getDecorators(fn) ?? [] : [];
    if (decorators.some((d) => ROUTE_DECORATORS.test(decoratorName(d)))) h = true;
    else for (const p of fn.parameters ?? []) {
      if (ts.isIdentifier(p.name) && ['request', 'response'].includes(kindOfSymbol(symbolOf(p.name)))) { h = true; break; }
    }
    handlerMemo.set(fn, h);
    return h;
  }
  /** The declaration of a module-level variable an expression is rooted in, or null. */
  function moduleLevelDecl(expr) {
    const root = rootIdentifier(expr);
    if (!ts.isIdentifier(root)) return null;
    let sym;
    try { sym = checker.getSymbolAtLocation(root); } catch { return null; }
    const d = sym?.declarations?.[0];
    if (!d || !ts.isVariableDeclaration(d)) return null;
    const stmt = d.parent?.parent;
    if (!stmt || !ts.isVariableStatement(stmt) || !ts.isSourceFile(stmt.parent)) return null;
    if (!rootNames.has(resolve(d.getSourceFile().fileName))) return null;
    return { decl: d, isConst: (d.parent.flags & ts.NodeFlags.Const) !== 0, init: d.initializer };
  }
  const sharedState = [];
  const sharedSeen = new Set();
  function checkSharedWrite(node, target, how) {
    if (!collecting) return;
    const fn = enclosingFn(node);
    if (!isHandler(fn)) return;
    const m = moduleLevelDecl(target);
    if (!m) return;
    if (how === 'assign' && m.isConst) return;
    if (how !== 'assign' && m.init && !(ts.isObjectLiteralExpression(m.init) || ts.isArrayLiteralExpression(m.init) || (ts.isNewExpression(m.init) && /^(Map|Set|WeakMap|Array|Object)$/.test(m.init.expression.getText())))) return;
    const k = `${rel(node.getSourceFile().fileName)}:${lineOf(node)}`;
    if (sharedSeen.has(k)) return;
    sharedSeen.add(k);
    sharedState.push({ node, decl: m.decl });
  }

  function checkSinks(call, isNew, name, receiver, receiverText, argTaints, receiverTaint) {
    if (receiver && /^(set|add|push|unshift|splice|delete|clear|fill|sort|reverse|assign)$/.test(name)) checkSharedWrite(call, receiver, 'mutate');
    const sf = call.getSourceFile();
    const inBrowser = browser(sf);
    const mod = moduleOf(call.expression);
    const recvType = receiver ? typeStr(receiver) : '';
    const bare = !receiver;
    for (const spec of S.SINKS) {
      const w = spec.where;
      if (!w.method && !w.bare && !w.orMethod) continue;
      if (w.browser && !inBrowser) continue;
      if (w.isNew && !isNew) continue;
      let nameOk = false;
      if (w.method) nameOk = w.method instanceof Set ? w.method.has(name) : w.method.test(name);
      if (w.bare && bare && w.bare.test(name)) nameOk = true;
      if (w.orMethod && !bare && w.orMethod.test(name)) nameOk = true;
      if (w.method && !w.bare && !w.orMethod && bare && !w.module) nameOk = false;
      if (!nameOk) continue;
      if (w.module) {
        if (mod) { if (!w.module.test(mod)) continue; }
        else if (!(w.bare && bare) && !(receiver && /^(fs|fsp|fsPromises|promises|cp|childProcess|child_process|vm|net|tls|dns|http|https|http2|crypto|path|zlib|os)$/.test(receiverText.split('.')[0]))) continue;
      }
      if (w.receiver === 'response' && !(receiver && isResponse(receiver))) continue;
      if (w.receiver === 'logger' && !(receiver && isLogger(receiver))) continue;
      if (w.receiverType && !(receiver && w.receiverType.test(recvType))) continue;
      if (w.receiverName && !(receiver && w.receiverName.test(receiverText))) continue;
      if (w.stringReceiver && !(receiver && stringish(receiver))) continue;
      const positions = spec.args.includes('*') ? call.arguments.map((_, i) => i) : spec.args;
      for (const i of positions) {
        const arg = call.arguments[i];
        if (!arg || !argTaints[i] || !argTaints[i].size) continue;
        if (w.stringArg && !stringish(arg)) continue;
        if (w.numberArg && !numberish(arg)) continue;
        if (w.objectArg && !objectish(arg)) continue;
        if (w.concatenatedArg && !(ts.isTemplateExpression(arg) || (ts.isBinaryExpression(arg) && arg.operatorToken.kind === ts.SyntaxKind.PlusToken))) continue;
        if (w.urlArgWithQuery && !/[?&]/.test(arg.getText())) continue;
        if (w.regexFromTaint && (ts.isRegularExpressionLiteral(arg) || ts.isStringLiteralLike(arg))) continue;
        if (w.idArg && !/^(string|number)\b/.test(typeStr(arg))) continue;
        recordHit(spec, call, argTaints[i], arg, i, { debug: spec.debugKinds && S.DEBUG_LOG_METHODS.has(name) });
      }
    }
  }

  function assignment(node) {
    const K = ts.SyntaxKind;
    const lhs = node.left;
    const rhsTaint = taintOf(node.right);
    const lhsText = lhs.getText().replace(/\s+/g, '');
    const sf = node.getSourceFile();
    if (ts.isIdentifier(lhs)) checkSharedWrite(node, lhs, 'assign');
    else if (ts.isPropertyAccessExpression(lhs) || ts.isElementAccessExpression(lhs)) checkSharedWrite(node, lhs, 'mutate');
    if (ts.isIdentifier(lhs)) { addTaint(symbolOf(lhs), rhsTaint, rhsTaint.size ? step(node, 'through') : null); }
    else if (ts.isPropertyAccessExpression(lhs) || ts.isElementAccessExpression(lhs)) {
      if (ts.isElementAccessExpression(lhs)) {
        const kt = taintOf(lhs.argumentExpression);
        if (kt.size && collecting && !numberish(lhs.argumentExpression)) recordHit(sinkById('prototype-pollution-key'), node, kt, lhs.argumentExpression);
      }
      if (lhs.expression.kind === K.ThisKeyword && ts.isPropertyAccessExpression(lhs)) addTaint(symbolOf(lhs.name), rhsTaint, rhsTaint.size ? step(node, 'through') : null);
      else {
        const root = rootIdentifier(lhs);
        if (ts.isIdentifier(root)) {
          const sym = symbolOf(root);
          // Do not taint the response, request or logger object through writes to it.
          const fieldTaint = ts.isPropertyAccessExpression(lhs) && lhs.expression === root ? rhsTaint.under(lhs.name.text) : ts.isElementAccessExpression(lhs) && lhs.expression === root && ts.isStringLiteralLike(lhs.argumentExpression) ? rhsTaint.under(lhs.argumentExpression.text) : rhsTaint;
          if (!['response', 'request', 'logger'].includes(kindOfSymbol(sym)) && !isResponse(root)) addTaint(sym, fieldTaint, rhsTaint.size ? step(node, 'through') : null);
        } else if (root.kind === K.ThisKeyword && ts.isPropertyAccessExpression(lhs.expression)) addTaint(symbolOf(lhs.expression.name), rhsTaint, rhsTaint.size ? step(node, 'through') : null);
        if (ts.isPropertyAccessExpression(lhs) && S.PRIVACY_NAME.test(lhs.name.text) && rhsTaint.size === 0 && ts.isIdentifier(root) && !ts.isStringLiteralLike(node.right)) addTaint(symbolOf(root), privacySource(node.right, lhs.name.text, node).under(lhs.name.text));
      }
    } else if (ts.isObjectLiteralExpression(lhs) || ts.isArrayLiteralExpression(lhs)) {
      // Destructuring assignment: every target gets the taint.
      const targets = ts.isObjectLiteralExpression(lhs) ? lhs.properties.map((p) => (ts.isShorthandPropertyAssignment(p) ? p.name : ts.isPropertyAssignment(p) ? p.initializer : null)).filter(Boolean) : lhs.elements;
      for (const t of targets) if (ts.isIdentifier(t)) addTaint(symbolOf(t), rhsTaint, step(node, 'through'));
    }
    if (collecting && rhsTaint.size) {
      for (const spec of S.SINKS) {
        if (!spec.where.assignTarget) continue;
        if (spec.where.browser && !browser(sf)) continue;
        if (spec.where.assignTarget.test(lhsText)) recordHit(spec, node, rhsTaint, node.right);
      }
    }
  }

  // --- Statements ---------------------------------------------------------------------------------
  function visitFunction(fn) {
    const info = ensureFn(fn);
    if (info.visitedPass === passNo) return;
    info.visitedPass = passNo;
    for (const p of fn.parameters) if (p.initializer) taintOf(p.initializer);
    if (!fn.body) return;
    if (ts.isBlock(fn.body)) visitNode(fn.body);
    else { const t = taintOf(fn.body); if (info.returnTaint.addAll(t.mapped((f) => f.with(step(fn.body, 'through'))))) changed = true; }
  }

  function visitNode(node) {
    if (!node) return;
    if (isFnLike(node)) { visitFunction(node); return; }
    const K = ts.SyntaxKind;
    switch (node.kind) {
      case K.VariableDeclaration: {
        if (node.initializer) {
          const t = taintOf(node.initializer);
          const fromRequest = isRequest(node.initializer);
          const kind = fromRequest ? 'request' : isResponse(node.initializer) ? 'response' : isErrorish(node.initializer) && t.size === 0 ? 'error' : null;
          bindPattern(node.name, t, t.size ? step(node, 'through') : null, { fromRequest, kind: kind ?? undefined });
        } else if (ts.isIdentifier(node.name)) { /* declared, assigned later */ }
        return;
      }
      case K.ReturnStatement: {
        const fn = enclosingFn(node);
        if (node.expression) {
          const t = taintOf(node.expression);
          if (fn) { const info = ensureFn(fn); if (info.returnTaint.addAll(t.mapped((f) => f.with(step(node, 'through'))))) changed = true; }
        }
        return;
      }
      case K.ThrowStatement: taintOf(node.expression); return;
      case K.ForOfStatement: case K.ForInStatement: {
        const t = taintOf(node.expression);
        if (ts.isVariableDeclarationList(node.initializer)) for (const d of node.initializer.declarations) bindPattern(d.name, t, t.size ? step(node, 'through') : null);
        visitNode(node.statement);
        return;
      }
      case K.CatchClause: {
        if (node.variableDeclaration) bindPattern(node.variableDeclaration.name, EMPTY, null, { kind: 'error' });
        visitNode(node.block);
        return;
      }
      case K.PropertyDeclaration: {
        if (node.initializer) { const t = taintOf(node.initializer); addTaint(symbolOf(node.name), t, t.size ? step(node, 'through') : null); if (isErrorish(node.initializer)) symKind.set(symbolOf(node.name), 'error'); }
        return;
      }
      case K.JsxAttribute: {
        const name = node.name.getText();
        if (node.initializer && ts.isJsxExpression(node.initializer) && node.initializer.expression) {
          const t = taintOf(node.initializer.expression);
          if (collecting && t.size) {
            for (const spec of S.SINKS) if (spec.where.jsxProp && spec.where.jsxProp.test(name)) recordHit(spec, node, t, node.initializer.expression);
            if (/^(href|src|action|formAction|srcDoc)$/.test(name)) recordHit(sinkById('xss-dom'), node, t.mapped((f) => f), node.initializer.expression);
          }
        }
        return;
      }
      case K.ExpressionStatement: taintOf(node.expression); return;
      case K.ImportDeclaration: case K.ImportEqualsDeclaration: case K.ExportDeclaration: case K.TypeAliasDeclaration: case K.InterfaceDeclaration: case K.EnumDeclaration: case K.ModuleDeclaration:
        if (node.kind === K.ModuleDeclaration && node.body) ts.forEachChild(node.body, visitNode);
        return;
      default:
        ts.forEachChild(node, (c) => { if (isExpression(c) && !ts.isJsxElement(c) && !ts.isJsxSelfClosingElement(c) && !ts.isJsxFragment(c)) taintOf(c); else visitNode(c); });
    }
  }

  // --- Driver -------------------------------------------------------------------------------------
  for (const sf of sourceFiles) registerImplementations(sf);
  let passNo = 0;
  for (passNo = 1; passNo <= MAX_PASSES; passNo++) {
    changed = false;
    memo = new Map();
    for (const sf of sourceFiles) visitNode(sf);
    log(`  dataflow: pass ${passNo}, ${store.size} tainted symbols, ${fnInfo.size} functions`);
    if (!changed) break;
  }
  // Final pass: collect sinks with the converged taint.
  collecting = true;
  memo = new Map();
  passNo++;
  for (const sf of sourceFiles) visitNode(sf);

  // --- Findings: expand parameter markers through call sites ---------------------------------------
  const findings = [];
  const seen = new Set();
  const expand = (flow, fn, depth, visited) => {
    // Returns the real-source flows that reach `flow` (a param marker of fn) through fn's call sites.
    const out = [];
    if (flow.source.kind !== 'param') { out.push(flow); return out; }
    if (depth > 7) return out;
    const info = fnInfo.get(fn);
    if (!info || info.id !== flow.source.fnId) return out;
    for (const site of info.callSites) {
      if (visited.has(site.call)) continue;
      const idx = flow.source.index;
      const restIndex = fn.parameters.findIndex((p) => p.dotDotDotToken);
      const incoming = restIndex >= 0 && idx === restIndex ? Taint.union(...site.argTaints.slice(idx)) : site.argTaints[idx];
      if (!incoming || !incoming.size) continue;
      const callStep = step(site.call, 'call');
      for (const g of incoming.values()) {
        const nv = new Set(visited); nv.add(site.call);
        const upstream = g.source.kind === 'param' && site.enclosing ? expand(g, site.enclosing, depth + 1, nv) : [g];
        for (const u of upstream) {
          const steps = [...u.steps, callStep, ...flow.steps];
          out.push(new Flow(u.source, steps.length > MAX_STEPS ? [...steps.slice(0, 6), ...steps.slice(-(MAX_STEPS - 6))] : steps, u.cleanFor ?? g.cleanFor, [...flow.fields, ...u.fields].slice(0, 4)));
          if (out.length > 200) return out;
        }
      }
    }
    return out;
  };
  for (const hit of sinkHits) {
    const kinds = hit.debug ? { ...hit.spec.kinds, ...hit.spec.debugKinds } : hit.spec.kinds;
    const sinkStep = step(hit.node, 'sink');
    const sinkFile = rel(hit.node.getSourceFile().fileName);
    for (const flow of hit.taint.values()) {
      const real = flow.source.kind === 'param' ? (hit.fn ? expand(flow, hit.fn, 0, new Set()) : []) : [flow];
      for (const f of real) {
        const category = kinds[f.source.kind];
        if (!category) continue;
        if (f.cleanFor && f.cleanFor.has(category)) continue;
        const perSink = f.source.kind === S.KIND.privacy || f.source.kind === S.KIND.error || f.source.kind === S.KIND.env;
        const key = `${category}|${sinkFile}:${lineOf(hit.node)}|${perSink ? f.source.kind : f.source.id}`;
        if (seen.has(key)) continue;
        seen.add(key);
        findings.push({
          category, sink: { file: sinkFile, line: lineOf(hit.node), end_line: hit.node.getSourceFile().getLineAndCharacterOfPosition(hit.node.getEnd()).line + 1, text: textOf(hit.node), argument: hit.keyNode ? hit.keyNode.getText().slice(0, 120) : '' },
          source: { kind: f.source.kind, label: f.source.label, file: f.source.file, line: f.source.line, text: f.source.text },
          trace: [...f.steps, sinkStep], rule: `fortify.dataflow.${hit.spec.id}`, abstract: hit.spec.abstract,
        });
      }
    }
  }
  for (const { node, decl } of sharedState) {
    findings.push({
      category: 'Cross-Session Contamination',
      sink: { file: rel(node.getSourceFile().fileName), line: lineOf(node), end_line: lineOf(node), text: textOf(node), argument: '' },
      source: { kind: 'shared', label: `module-level state ${decl.name.getText()}`, file: rel(decl.getSourceFile().fileName), line: lineOf(decl), text: textOf(decl) },
      trace: [step(decl, 'source'), step(node, 'sink')], rule: 'fortify.dataflow.cross-session-contamination',
      abstract: 'A request handler writes module-level state that every request (and every user) shares.',
    });
  }
  log(`  dataflow: ${sinkHits.length} sink reaches, ${findings.length} source→sink issues`);
  return { findings, stats: { files: sourceFiles.length, functions: fnInfo.size, passes: passNo - 1, sinks: sinkHits.length } };
}

export function dataflowInstanceId(f) {
  const norm = (s) => s.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${f.category}|${f.sink.file}|${norm(f.sink.text)}|${f.source.file}|${norm(f.source.text)}`).digest('hex').slice(0, 32).toUpperCase();
}

/** Reads a file list for a target; used by the scan driver to honour --tracked. */
export function readTextSafe(p) { try { return readFileSync(p, 'utf8'); } catch { return ''; } }
export function isFile(p) { try { return statSync(p).isFile(); } catch { return false; } }
