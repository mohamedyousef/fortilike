/**
 * fortilike: a Fortify-like static analysis for JavaScript and TypeScript repositories.
 *
 * Not Fortify. OpenText's Secure Coding Rulepacks are licensed and not reproducible; what this tool
 * reproduces is the shape of a Fortify scan: the categories and kingdoms, the Fortify Priority Order
 * (Impact and Likelihood = Accuracy x Confidence x Probability / 25), dataflow findings with a
 * source -> sink trace from Semgrep's taint analysis (open engine, rules in rules/), structural and
 * configuration rules, and a Developer-Workbook-style report with stable instance ids.
 *
 * Node 20.19+ and no dependencies. Semgrep runs from a pinned Docker image (default) or a local install.
 */
import { spawnSync } from 'node:child_process';
import { createHash } from 'node:crypto';
import { existsSync, mkdirSync, readdirSync, readFileSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, extname, join, relative, resolve, sep } from 'node:path';
import { fileURLToPath } from 'node:url';

export const VERSION = '0.1.0';
const HERE = dirname(fileURLToPath(import.meta.url));
const ROOT = resolve(HERE, '..');
const RULES_DIR = join(ROOT, 'rules');
const TAXONOMY = JSON.parse(readFileSync(join(ROOT, 'taxonomy', 'categories.json'), 'utf8'));
const CATEGORIES = TAXONOMY.categories;
const CWE_TO_CATEGORY = TAXONOMY.cwe_to_category;
const KINGDOMS = [...TAXONOMY.kingdoms, 'Other'];

export const SEMGREP_IMAGE =
  'docker.io/semgrep/semgrep:1.181.1@sha256:3db5c7af55eb1f512eac0abf0ab69a97b52c74b5e9a27314c221aee1a78d7ab2';
const COMMUNITY_PACKS = [
  'p/security-audit', 'p/owasp-top-ten', 'p/secrets', 'p/typescript', 'p/javascript', 'p/nodejs',
  'p/react', 'p/command-injection', 'p/xss', 'p/insecure-transport',
];
const DEFAULT_EXCLUDES = [
  'node_modules', 'dist', 'build', 'coverage', '.git', '.angular', '.cache', '.turbo', '.next', '.nuxt',
  '.vite', '.parcel-cache', '*.min.js', 'package-lock.json',
];
const NEUTRAL_SEMGREPIGNORE =
  'node_modules/\ndist/\nbuild/\ncoverage/\n.git/\n.angular/\n.cache/\n.turbo/\n.next/\n.nuxt/\n.vite/\n.parcel-cache/\n*.min.js\n';
export const PRIORITIES = ['Critical', 'High', 'Medium', 'Low'];
const CODE_EXTS = new Set(['.js', '.jsx', '.mjs', '.cjs', '.ts', '.tsx', '.mts', '.cts']);

// --- Model ----------------------------------------------------------------------------------------

/** Fortify Priority Order from Impact and Likelihood, as Audit Workbench folders them. */
export function fortifyPriority(impact, probability, accuracy, confidence) {
  const likelihood = (accuracy * confidence * probability) / 25;
  if (impact >= 2.5 && likelihood >= 2.5) return ['Critical', likelihood];
  if (impact >= 2.5) return ['High', likelihood];
  if (likelihood >= 2.5) return ['Medium', likelihood];
  return ['Low', likelihood];
}

/** Stable across runs when the line moves: rule, path and the normalized sink text. */
export function instanceId(rule, path, snippet) {
  const norm = snippet.replace(/\s+/g, ' ').trim();
  return createHash('sha256').update(`${rule}|${path}|${norm}`).digest('hex').slice(0, 32).toUpperCase();
}

export function classify(rel) {
  const p = rel.split(sep).join('/');
  if (/(^|\/)(test|tests|__tests__|e2e|spec|specs|fixtures?)\/|\.(test|spec)\.[cm]?[jt]sx?$|\/test-support\/|\/testing\//.test(p)) return 'test';
  if (p.includes('/templates/') || p.startsWith('templates/')) return 'template';
  if (p.startsWith('examples/') || p.includes('/examples/') || p.startsWith('example/')) return 'example';
  if (p.startsWith('.github/') || /(bitbucket-pipelines\.yml|\.gitlab-ci\.yml|Jenkinsfile)$/.test(p) || p.includes('/ci/')) return 'ci';
  if (/(^|\/)(tool|tools|scripts?|bin)\//.test(p)) return 'tooling';
  if (/\.(md|mdx|txt)$/.test(p) || p.includes('/docs/') || p.startsWith('docs/')) return 'docs';
  if (!CODE_EXTS.has(extname(p).toLowerCase())) return 'config';
  return 'production';
}

function readLines(root, rel) {
  try {
    return readFileSync(join(root, rel), 'utf8').split(/\r?\n/);
  } catch {
    return [];
  }
}

function snippetOf(lines, start, end) {
  const chunk = lines.slice(Math.max(0, start - 1), Math.max(start, Math.min(end, start + 4)));
  const text = chunk.map((l) => l.trimEnd()).join('\n');
  return text.length <= 400 ? text : text.slice(0, 400) + ' …';
}

function categoryDefaults(category) {
  return CATEGORIES[category] ?? { kingdom: 'Other', cwe: [], impact: 2, probability: 3, accuracy: 4, confidence: 4 };
}

// --- Semgrep --------------------------------------------------------------------------------------

function which(program) {
  const r = spawnSync(process.platform === 'win32' ? 'where' : 'which', [program], { encoding: 'utf8' });
  return r.status === 0;
}

class Semgrep {
  constructor({ engine, image, target, excludes, jobs, scratch }) {
    this.engine = engine;
    this.image = image;
    this.target = target;
    this.excludes = excludes;
    this.jobs = jobs;
    this.scratch = scratch;
    if (engine === 'local' && !which('semgrep')) throw new Error('semgrep is not on PATH; install it or use --semgrep docker');
    if (engine === 'docker' && !which('docker')) throw new Error('docker is not on PATH; install Semgrep locally and use --semgrep local');
  }

  /**
   * Semgrep's built-in ignore list skips test/ and tests/ when a repository has no .semgrepignore of
   * its own; Fortify reads the tests. A target without one is mounted read-only under a writable
   * scratch root (under the output folder, which Docker Desktop shares) that carries a neutral
   * .semgrepignore, and Semgrep is told that root is the project root.
   */
  scratchRoot() {
    if (existsSync(join(this.target, '.semgrepignore'))) return undefined;
    const root = join(this.scratch, '.semgrep-root');
    mkdirSync(join(root, 'src'), { recursive: true });
    writeFileSync(join(root, '.semgrepignore'), NEUTRAL_SEMGREPIGNORE);
    return root;
  }

  base(configs) {
    const common = ['scan', '--metrics=off', '--quiet', '--timeout', '60', '--timeout-threshold', '3',
      '--max-target-bytes', '3000000', '--disable-version-check'];
    for (const e of this.excludes) common.push('--exclude', e);
    if (this.jobs) common.push('--jobs', String(this.jobs));
    if (this.engine === 'docker') {
      const cfgs = configs.map((c) => c.replace(RULES_DIR, '/rules'));
      const cmd = ['run', '--rm', '-v', `${RULES_DIR}:/rules:ro`];
      const root = this.scratchRoot();
      if (root) {
        cmd.push('-v', `${root}:/work`, '-v', `${this.target}:/work/src:ro`, '-w', '/work', this.image, 'semgrep', ...common,
          '--semgrepignore-v2', '--project-root', '/work');
        for (const e of this.excludes) if (e.replace(/^\/+|\/+$/g, '').includes('/')) cmd.push('--exclude', 'src/' + e.replace(/^\/+/, ''));
        for (const c of cfgs) cmd.push('--config', c);
        return { program: 'docker', args: [...cmd, '/work/src'], prefix: '/work/src/' };
      }
      cmd.push('-v', `${this.target}:/src:ro`, '-w', '/src', this.image, 'semgrep', ...common);
      for (const c of cfgs) cmd.push('--config', c);
      return { program: 'docker', args: [...cmd, '/src'], prefix: '/src/' };
    }
    const args = [...common];
    for (const c of configs) args.push('--config', c);
    return { program: 'semgrep', args: [...args, this.target], prefix: this.target.replace(/\/+$/, '') + '/' };
  }

  run(configs, extra) {
    const { program, args, prefix } = this.base(configs);
    const r = spawnSync(program, [...args, ...extra], { encoding: 'utf8', maxBuffer: 1024 * 1024 * 1024 });
    return { stdout: r.stdout ?? '', stderr: r.stderr ?? '', status: r.status, prefix };
  }

  runJson(configs) {
    const r = this.run(configs, ['--json']);
    if (!r.stdout.trim()) throw new Error(`semgrep produced no output (exit ${r.status}):\n${r.stderr.slice(-2000)}`);
    try {
      return { data: JSON.parse(r.stdout), prefix: r.prefix };
    } catch {
      throw new Error(`semgrep output is not JSON (exit ${r.status}):\n${r.stdout.slice(0, 500)}\n${r.stderr.slice(-1500)}`);
    }
  }

  runTextTraces(configs) {
    return this.run(configs, ['--dataflow-traces', '--no-force-color']).stdout;
  }

  version() {
    const r = this.engine === 'docker'
      ? spawnSync('docker', ['run', '--rm', this.image, 'semgrep', '--version'], { encoding: 'utf8' })
      : spawnSync('semgrep', ['--version'], { encoding: 'utf8' });
    const lines = (r.stdout ?? '').trim().split('\n').filter(Boolean);
    return lines.length ? lines[lines.length - 1] : '?';
  }
}

const LINE_RE = /^\s*(\d+)┆(.*)$/;
const RULE_RE = /❱\s*([\w.\-/]+)\s*$/;
const SEP_RE = /^\s*⋮┆-+\s*$/;

function ruleSuffix(checkId) {
  const i = checkId.indexOf('fortify.');
  return i >= 0 ? checkId.slice(i) : checkId;
}

/**
 * Semgrep CE prints taint traces in its text output only (the JSON needs a login).
 * Returns a Map "rule|path|sinkLine" -> [{role, line, text}].
 */
export function parseTraces(text) {
  const traces = new Map();
  let path = null;
  let rule = null;
  let section = null;
  let sinkLine = null;
  let steps = [];
  const flush = () => {
    if (rule && path && sinkLine !== null && steps.length) traces.set(`${ruleSuffix(rule)}|${path}|${sinkLine}`, steps);
    steps = [];
    sinkLine = null;
    section = null;
  };
  for (const raw of text.split('\n')) {
    const line = raw.trimEnd();
    if (!line.trim()) continue;
    if (SEP_RE.test(line)) { flush(); continue; }
    const m = RULE_RE.exec(line);
    if (m && line.includes('❱') && !LINE_RE.test(line)) { flush(); rule = m[1]; continue; }
    const stripped = line.trim();
    if (stripped.startsWith('/') && !stripped.includes('┆') && !stripped.includes(' ')) { flush(); path = stripped; continue; }
    if (stripped.startsWith('Taint comes from')) { section = 'source'; continue; }
    if (stripped.startsWith('Taint flows through')) { section = 'through'; continue; }
    if (stripped.startsWith('This is how taint reaches')) { section = 'sink'; continue; }
    const lm = LINE_RE.exec(line);
    if (lm) {
      const n = Number(lm[1]);
      const code = lm[2].trim();
      if (section === null) { if (sinkLine === null) sinkLine = n; continue; }
      steps.push({ role: section, line: n, text: code });
    }
  }
  flush();
  return traces;
}

function mapCommunity(meta, severity) {
  let cwes = meta.cwe ?? [];
  if (typeof cwes === 'string') cwes = [cwes];
  const ids = [];
  for (const c of cwes) { const m = /CWE-\d+/.exec(String(c)); if (m) ids.push(m[0]); }
  const category = ids.map((c) => CWE_TO_CATEGORY[c]).find(Boolean);
  if (category) {
    const d = CATEGORIES[category];
    const [priority, likelihood] = fortifyPriority(d.impact, d.probability, d.accuracy, 3);
    return { category, kingdom: d.kingdom, impact: d.impact, likelihood, priority, cwe: ids, owasp: [].concat(meta.owasp ?? []), abstract: '' };
  }
  let sub = meta.subcategory ?? meta.category ?? 'other';
  if (Array.isArray(sub)) sub = sub.join(', ');
  const [impact, probability] = { ERROR: [3, 3], WARNING: [2, 4] }[severity] ?? [1, 3];
  const [priority, likelihood] = fortifyPriority(impact, probability, 4, 3);
  return { category: `Other: ${sub}`, kingdom: 'Other', impact, likelihood, priority, cwe: ids, owasp: [].concat(meta.owasp ?? []), abstract: '' };
}

function semgrepResultsToFindings(data, prefix, root, traces, community) {
  const findings = [];
  const errors = (data.errors ?? []).filter((e) => e.level === 'error').map((e) => String(e.message ?? '').slice(0, 300));
  for (const r of data.results ?? []) {
    const path = r.path;
    const rel = path.startsWith(prefix) ? path.slice(prefix.length) : path;
    const start = r.start.line;
    const end = r.end.line;
    const extra = r.extra ?? {};
    const meta = extra.metadata ?? {};
    const lines = readLines(root, rel);
    const snippet = snippetOf(lines, start, end);
    let f;
    if (community) {
      f = { ...mapCommunity(meta, extra.severity ?? 'WARNING'), rule: r.check_id, engine: 'community' };
    } else {
      const fm = meta.fortify ?? {};
      const category = fm.category ?? 'Other';
      const d = categoryDefaults(category);
      const impact = Number(fm.impact ?? d.impact);
      const [priority, likelihood] = fortifyPriority(impact, Number(fm.probability ?? d.probability), Number(fm.accuracy ?? d.accuracy), Number(fm.confidence ?? d.confidence));
      f = { category, kingdom: fm.kingdom ?? d.kingdom, impact, likelihood, priority, cwe: [].concat(meta.cwe ?? []), owasp: [].concat(meta.owasp ?? []), abstract: fm.abstract ?? '', rule: ruleSuffix(r.check_id), engine: 'semgrep' };
    }
    const trace = traces.get(`${ruleSuffix(r.check_id)}|${path}|${start}`) ?? [];
    if (trace.length) f.engine = 'semgrep-taint';
    findings.push({
      instance_id: instanceId(f.rule, rel, start > 0 && start <= lines.length ? lines[start - 1] : snippet),
      rule: f.rule, category: f.category, kingdom: f.kingdom, priority: f.priority, impact: f.impact,
      likelihood: Math.round(f.likelihood * 100) / 100, path: rel, line: start, end_line: end, snippet,
      message: String(extra.message ?? '').trim(), abstract: f.abstract, kind: classify(rel), engine: f.engine,
      cwe: f.cwe, owasp: f.owasp, trace, status: 'existing',
    });
  }
  return { findings, errors };
}

// --- Structural rules for files Semgrep does not read as code ---------------------------------------

const SECRET_NAME = '(?:password|passwd|pwd|passphrase|secret|api[_-]?key|access[_-]?key|private[_-]?key|client[_-]?secret|credentials?|auth[_-]?token|access[_-]?token|refresh[_-]?token)';
const CONFIG_EXTS = new Set(['.json', '.yaml', '.yml', '.toml', '.ini', '.properties', '.cfg', '.conf', '.xml', '.npmrc', '.yarnrc']);
const LOCK_FILES = new Set(['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml', 'composer.lock', 'Cargo.lock', 'poetry.lock', 'pubspec.lock']);
const PLACEHOLDER = /^\s*$|^\$\{?|^<[^>]+>$|^\*+$|^x+$|^(?:changeme|example|placeholder|redacted|null|none|true|false|undefined)$|^\{\{|^\{$|^\[$|^[A-Za-z][A-Za-z_-]{0,30}$/i;

const isConfig = (rel, name) => (CONFIG_EXTS.has(extname(name).toLowerCase()) || name.startsWith('.env')) && !LOCK_FILES.has(name);
const isCode = (rel, name) => CODE_EXTS.has(extname(name).toLowerCase());
const isDockerfile = (rel, name) => name === 'Dockerfile' || name.startsWith('Dockerfile.') || name.endsWith('.Dockerfile');
const isWorkflow = (rel, name) => `/${rel}`.includes('/.github/workflows/') && /\.ya?ml$/.test(name);
/** Files Fortify reads besides code: configuration, keys and scripts (not Markdown). */
const isText = (rel, name) =>
  CONFIG_EXTS.has(extname(name).toLowerCase()) || ['.pem', '.key', '.crt', '.sh', '.bash', '.zsh', '.ps1', '.env'].includes(extname(name).toLowerCase())
  || name.startsWith('.env') || isDockerfile(rel, name);

export const STRUCTURAL = [
  { id: 'fortify.password-management-password-in-configuration-file', category: 'Password Management: Password in Configuration File',
    message: 'A configuration key named after a credential holds a value. Configuration in the repository is in every clone; supply credentials at deployment, and keep examples empty.',
    confidence: 4, applies: isConfig, pattern: new RegExp(`^\\s*["']?[\\w.-]*${SECRET_NAME}[\\w.-]*["']?\\s*[:=]\\s*["']?(?<value>[^\\s"',#]+)`, 'i') },
  { id: 'fortify.password-management-password-in-url', category: 'Password Management: Hardcoded Password',
    message: 'A URL in a configuration or text file carries user:password credentials.',
    confidence: 5, applies: (rel, name) => isText(rel, name) && !isCode(rel, name), pattern: /[a-z][a-z0-9+.-]*:\/\/[^/\s:@'"`]+:(?<value>[^@\s'"`/]+)@/ },
  { id: 'fortify.key-management-hardcoded-private-key', category: 'Key Management: Hardcoded Encryption Key',
    message: 'A PEM private key is in the repository. Keys belong in a secret store or outside the tree; a test key is made when the tests run.',
    confidence: 5, applies: (rel, name) => isText(rel, name) && !isCode(rel, name), pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/ },
  { id: 'fortify.password-management-password-in-comment', category: 'Password Management: Password in Comment',
    message: 'A comment names a password, secret or key. Fortify reports every such comment, whether or not a value follows; reword it (say "credential" or "sign-in") or drop it before the scan.',
    confidence: 4, applies: (rel, name) => isCode(rel, name) || isConfig(rel, name) || isDockerfile(rel, name) || /\.(sh|bash|zsh|ps1|hcl|tf|toml|ini|cfg|conf|properties|Caddyfile)$/.test(name) || name === 'Caddyfile',
    pattern: /^\s*(?:\/\/|\*(?!\s*\w+\s*[=;(])|\/\*|#(?![\w$]+\s*[=;:(])|<!--|--\s|;)(?!.*\b(?:password-less|passwordless)\b).*\b(?:passwords?|passwd|pwd|passphrase|secrets?|api[_-]?keys?|client[_-]?secrets?|private[_-]?keys?)\b/i },
  { id: 'fortify.credential-management-npm-token', category: 'Credential Management: Hardcoded API Credentials',
    message: 'An npm configuration file carries a registry token or password. Supply it from the environment (${NPM_TOKEN}) at build time.',
    confidence: 5, applies: (rel, name) => ['.npmrc', '.yarnrc', '.yarnrc.yml'].includes(name), pattern: /(?:_authToken|_auth|_password|npmAuthToken|npmAuthIdent)\s*[=:]\s*["']?(?<value>[^\s"'$][^\s"']*)/ },
  { id: 'fortify.insecure-transport-package-url', category: 'Insecure Transport',
    message: 'A dependency is fetched over plain http or git://, so a network position can replace the package.',
    confidence: 5, applies: (rel, name) => name === 'package.json', pattern: /["'](?<value>(?:http|git):\/\/[^"']+)["']/ },
  { id: 'fortify.build-misconfiguration-install-script-download', category: 'Build Misconfiguration',
    message: 'A package script downloads and runs code (curl or wget piped into a shell, or npx of an unpinned package) during install or build.',
    confidence: 4, applies: (rel, name) => name === 'package.json', pattern: /"(?:pre|post)?(?:install|prepare|build|start)"\s*:\s*"[^"]*(?:(?:curl|wget)\b[^"|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b|npx\s+(?!--no-install|--no)[\w@/.-]+(?<![\d.]\d))/ },
  { id: 'fortify.password-management-compose-environment', category: 'Password Management: Password in Configuration File',
    message: 'A compose or Kubernetes environment entry sets a credential inline. Use a secret or an env_file that is not committed.',
    confidence: 4, applies: (rel, name) => /^(docker-)?compose(\..+)?\.ya?ml$/.test(name) || /\.ya?ml$/.test(name), pattern: new RegExp(`^\\s*-\\s*["']?[\\w.-]*${SECRET_NAME}[\\w.-]*=(?<value>[^\\s"'#$][^\\s"']*)`, 'i') },
  { id: 'fortify.password-management-json-key', category: 'Password Management: Hardcoded Password',
    message: 'A JSON file (data, fixtures, generated API reference, translations) carries a key named like a credential with a string value. Fortify reads JSON too; keep such values out of the repository or make the key name neutral.',
    confidence: 3, applies: (rel, name) => name.endsWith('.json') && !LOCK_FILES.has(name) && name !== 'package.json' && name !== 'tsconfig.json', pattern: new RegExp(`"[\\w.-]*(?:passw(?:or)?d|passwd|pwd|passphrase|secret|api[_-]?key|private[_-]?key|client[_-]?secret|access[_-]?token|refresh[_-]?token|auth[_-]?token)[\\w.-]*"\\s*:\\s*"(?<value>[^"]{4,})"`, 'i') },
  { id: 'fortify.dockerfile-misconfiguration-default-user', category: 'Dockerfile Misconfiguration',
    message: "The image's final stage sets no USER, so its process runs as root.",
    confidence: 5, applies: isDockerfile, perFile: true, pattern: /^\s*FROM\s+(?!scratch\b)\S+(?![\s\S]*^\s*USER\s)/m },
  { id: 'fortify.build-misconfiguration-unverified-download', category: 'Build Misconfiguration',
    message: 'A download is piped straight into a shell: whatever the server (or the path to it) returns runs during the build.',
    confidence: 5, applies: (rel, name) => isDockerfile(rel, name) || /\.(sh|bash|zsh)$/.test(name) || isWorkflow(rel, name), pattern: /(?:curl|wget)\b[^|\n]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b/ },
  { id: 'fortify.build-misconfiguration-mutable-action-reference', category: 'Build Misconfiguration',
    message: 'A GitHub Action is referenced by a tag or branch, which its owner (or an attacker with their account) can move; pin the commit SHA.',
    confidence: 5, applies: isWorkflow, pattern: /^\s*-?\s*uses:\s*(?<value>[\w.-]+\/[\w.-]+(?:\/[\w./-]+)?@(?![0-9a-f]{40}\b)[\w.-]+)/ },
  { id: 'fortify.insecure-transport-npm-tls-off', category: 'Insecure Transport',
    message: 'npm is told not to verify TLS certificates, so a registry on the path can serve any package.',
    confidence: 5, applies: (rel, name) => ['.npmrc', '.yarnrc'].includes(name) || isDockerfile(rel, name) || isWorkflow(rel, name) || name.endsWith('.sh'),
    pattern: /strict-ssl\s*(?:=|\s)\s*false|npm_config_strict_ssl\s*=\s*false|NODE_TLS_REJECT_UNAUTHORIZED\s*[=:]\s*["']?0/ },
  { id: 'fortify.insecure-transport-config-url', category: 'Insecure Transport',
    message: 'A configuration value names a plain-http address that is not loopback.',
    confidence: 3, applies: isConfig,
    pattern: /["'= ](?<value>http:\/\/(?!(?:localhost|127\.\d+\.\d+\.\d+|0\.0\.0\.0|\[::1?\]|host\.docker\.internal|www\.w3\.org|json-schema\.org|schemas?\.[\w.-]+|xmlns\.[\w.-]+|ns\.adobe\.com|purl\.org)(?:[:/]|$))(?![\w.-]+\.(?:invalid|test|example|localhost|local)(?:[:/]|$))[^\s"'<>]+)/ },
];

function globToRegExp(glob) {
  const re = glob.replace(/[.+^${}()|[\]\\]/g, '\\$&').replace(/\*\*/g, '\0').replace(/\*/g, '[^/]*').replace(/\?/g, '[^/]').replace(/\0/g, '.*');
  return new RegExp(`^${re}$`);
}

function excluded(rel, name, excludes) {
  for (const g of excludes) {
    const gg = g.replace(/\/+$/, '');
    if (globToRegExp(gg).test(name) || globToRegExp(gg).test(rel) || rel.startsWith(gg + '/')) return true;
  }
  return false;
}

export function structuralScan(root, excludes) {
  const findings = [];
  const walk = (dir) => {
    let entries;
    try { entries = readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = join(dir, e.name);
      const rel = relative(root, full).split(sep).join('/');
      if (excluded(rel, e.name, excludes)) continue;
      if (e.isDirectory()) { walk(full); continue; }
      if (!e.isFile()) continue;
      const rules = STRUCTURAL.filter((r) => r.applies(rel, e.name));
      if (!rules.length) continue;
      let text;
      try { if (statSync(full).size > 2_000_000) continue; text = readFileSync(full, 'utf8'); } catch { continue; }
      const lines = text.split(/\r?\n/);
      const kind = classify(rel);
      for (const rule of rules) {
        const d = categoryDefaults(rule.category);
        const [priority, likelihood] = fortifyPriority(d.impact, d.probability, d.accuracy, rule.confidence);
        if (rule.perFile) {
          const m = rule.pattern.exec(text);
          if (m) findings.push(makeStructural(rule, rel, text.slice(0, m.index).split('\n').length, lines, kind, priority, likelihood, d));
          continue;
        }
        lines.forEach((line, i) => {
          if (line.length > 2000) return;
          const m = rule.pattern.exec(line);
          if (!m) return;
          const value = m.groups?.value;
          if (value !== undefined && PLACEHOLDER.test(value.replace(/^['"]+|['"]+$/g, ''))) return;
          findings.push(makeStructural(rule, rel, i + 1, lines, kind, priority, likelihood, d));
        });
      }
    }
  };
  walk(root);
  return findings;
}

function makeStructural(rule, rel, line, lines, kind, priority, likelihood, d) {
  const snippet = snippetOf(lines, line, line);
  return {
    instance_id: instanceId(rule.id, rel, line > 0 && line <= lines.length ? lines[line - 1] : snippet),
    rule: rule.id, category: rule.category, kingdom: d.kingdom, priority, impact: d.impact,
    likelihood: Math.round(likelihood * 100) / 100, path: rel, line, end_line: line, snippet,
    message: rule.message, abstract: '', kind, engine: 'structural', cwe: [...(d.cwe ?? [])], owasp: [], trace: [], status: 'existing',
  };
}

// --- Reports --------------------------------------------------------------------------------------

export function summarize(findings) {
  const byPriority = Object.fromEntries(PRIORITIES.map((p) => [p, 0]));
  const byKingdom = {};
  const byCategory = {};
  const byKind = {};
  for (const f of findings) {
    byPriority[f.priority] = (byPriority[f.priority] ?? 0) + 1;
    (byKingdom[f.kingdom] ??= Object.fromEntries(PRIORITIES.map((p) => [p, 0])))[f.priority] += 1;
    (byCategory[f.category] ??= Object.fromEntries(PRIORITIES.map((p) => [p, 0])))[f.priority] += 1;
    byKind[f.kind] = (byKind[f.kind] ?? 0) + 1;
  }
  return { by_priority: byPriority, by_kingdom: byKingdom, by_category: byCategory, by_kind: byKind };
}

const sum = (o) => Object.values(o).reduce((a, b) => a + b, 0);
const order = Object.fromEntries(PRIORITIES.map((p, i) => [p, i]));
const sortFindings = (fs) => [...fs].sort((a, b) => order[a.priority] - order[b.priority] || a.category.localeCompare(b.category) || a.path.localeCompare(b.path) || a.line - b.line);
const firstLine = (f) => f.snippet.split('\n')[0];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const anchor = (s) => s.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-|-$/g, '');

function writeJson(path, info, findings) {
  writeFileSync(path, JSON.stringify({ fortilike: VERSION, scan: info, summary: summarize(findings), findings }, null, 2));
}

function writeSarif(path, info, findings) {
  const level = { Critical: 'error', High: 'error', Medium: 'warning', Low: 'note' };
  const rules = new Map();
  const results = findings.map((f) => {
    if (!rules.has(f.rule)) rules.set(f.rule, {
      id: f.rule, name: f.category, shortDescription: { text: f.category }, fullDescription: { text: f.abstract || f.message },
      defaultConfiguration: { level: level[f.priority] }, properties: { kingdom: f.kingdom, cwe: f.cwe, owasp: f.owasp, fortifyPriority: f.priority },
    });
    const res = {
      ruleId: f.rule, level: level[f.priority], message: { text: f.message },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.path }, region: { startLine: f.line, endLine: f.end_line, snippet: { text: f.snippet } } } }],
      partialFingerprints: { 'fortilike/instance': f.instance_id },
      properties: { category: f.category, kingdom: f.kingdom, priority: f.priority, impact: f.impact, likelihood: f.likelihood, kind: f.kind, engine: f.engine, status: f.status },
    };
    if (f.trace.length) res.codeFlows = [{ threadFlows: [{ locations: f.trace.map((s) => ({
      location: { physicalLocation: { artifactLocation: { uri: f.path }, region: { startLine: s.line, snippet: { text: s.text } } }, message: { text: s.role } } })) }] }];
    return res;
  });
  writeFileSync(path, JSON.stringify({
    $schema: 'https://json.schemastore.org/sarif-2.1.0.json', version: '2.1.0',
    runs: [{ tool: { driver: { name: 'fortilike', version: VERSION, rules: [...rules.values()] } }, results, properties: info }],
  }, null, 2));
}

function writeMarkdown(path, info, findings) {
  const s = summarize(findings);
  const out = [`# ${info.name}: Fortify-like scan`, '',
    `${info.date} · ${info.files_scanned} files · engine ${info.engine} · rules ${info.rules} · ${findings.length} issues. Not a Fortify scan: categories and priorities follow Fortify's taxonomy; the rules are this tool's.`, '',
    '| Critical | High | Medium | Low |', '|---|---|---|---|', '| ' + PRIORITIES.map((p) => s.by_priority[p]).join(' | ') + ' |', ''];
  if (info.baseline) out.push(`Against the baseline: ${findings.filter((f) => f.status === 'new').length} new, ${info.baseline_fixed} gone.`, '');
  out.push('| Where | Issues |', '|---|---|', ...Object.entries(s.by_kind).sort().map(([k, v]) => `| ${k} | ${v} |`), '');
  out.push('| Category | Kingdom | Critical | High | Medium | Low |', '|---|---|---|---|---|---|');
  for (const [cat, c] of Object.entries(s.by_category).sort((a, b) => sum(b[1]) - sum(a[1]) || a[0].localeCompare(b[0]))) {
    const kingdom = findings.find((f) => f.category === cat).kingdom;
    out.push(`| ${cat} | ${kingdom} | ${PRIORITIES.map((p) => c[p]).join(' | ')} |`);
  }
  out.push('');
  let current = null;
  for (const f of sortFindings(findings)) {
    const head = `## ${f.category} (${f.priority})`;
    if (head !== current) { current = head; out.push(head, '', f.abstract || f.message.split('. ')[0] + '.', ''); }
    const flags = [f.kind, ...(f.status === 'new' ? ['new'] : []), ...(f.trace.length ? ['trace'] : [])];
    out.push(`- \`${f.path}:${f.line}\` (${flags.join(', ')}) \`${f.instance_id.slice(0, 8)}\`: \`${firstLine(f).slice(0, 140).replace(/`/g, "'")}\``);
    for (const st of f.trace) out.push(`  - ${st.role} L${st.line}: \`${st.text.slice(0, 120).replace(/`/g, "'")}\``);
  }
  out.push('');
  writeFileSync(path, out.join('\n'));
}

const HTML_CSS = `
:root{--bg:#fff;--fg:#1b1f24;--muted:#5b6470;--line:#e3e7ec;--card:#f6f8fa;--crit:#b3261e;--high:#d9480f;--med:#b07d00;--low:#2f6fde;--mono:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--bg:#0e1116;--fg:#e6e9ee;--muted:#9aa4b2;--line:#273040;--card:#161b24;--low:#6ea0ff;--med:#e0a915}}
:root[data-theme=dark]{--bg:#0e1116;--fg:#e6e9ee;--muted:#9aa4b2;--line:#273040;--card:#161b24;--low:#6ea0ff;--med:#e0a915}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.5 Inter,system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 64px}h1{font-size:26px;margin:0 0 4px}h2{font-size:20px;margin:36px 0 12px;padding-top:8px;border-top:1px solid var(--line)}h3{font-size:16px;margin:24px 0 8px}
.sub{color:var(--muted)}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:12px;margin:16px 0}
.tile{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:12px 14px}.tile b{display:block;font-size:28px;line-height:1.1}.tile span{color:var(--muted);font-size:13px}
table{border-collapse:collapse;width:100%;font-size:14px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid var(--line);vertical-align:top}th{color:var(--muted);font-weight:600}td.n{text-align:right;font-variant-numeric:tabular-nums}
.p{display:inline-block;padding:1px 8px;border-radius:999px;color:#fff;font-size:12px;font-weight:600}.p.Critical{background:var(--crit)}.p.High{background:var(--high)}.p.Medium{background:var(--med)}.p.Low{background:var(--low)}
.tag{display:inline-block;padding:0 6px;border:1px solid var(--line);border-radius:6px;font-size:12px;color:var(--muted);margin-left:6px}.tag.new{color:var(--crit);border-color:var(--crit)}
details{border:1px solid var(--line);border-radius:10px;margin:8px 0;background:var(--card)}summary{cursor:pointer;padding:10px 14px;font-weight:600}summary small{font-weight:400;color:var(--muted)}
.issue{padding:0 14px 14px}.loc{font-family:var(--mono);font-size:13px}pre{margin:6px 0 0;padding:10px 12px;background:var(--bg);border:1px solid var(--line);border-radius:8px;overflow:auto;font:12.5px/1.45 var(--mono)}
.trace{margin:8px 0 0;font-family:var(--mono);font-size:12.5px}.trace div{padding:2px 0}.trace .role{display:inline-block;width:64px;color:var(--muted)}.msg{color:var(--muted);font-size:14px;margin:8px 0 0}
.bar{height:10px;border-radius:5px;background:var(--line);overflow:hidden;display:flex}.bar i{display:block;height:100%}.bar .Critical{background:var(--crit)}.bar .High{background:var(--high)}.bar .Medium{background:var(--med)}.bar .Low{background:var(--low)}
@media(max-width:600px){h1{font-size:22px}.tile b{font-size:22px}}
`;

function writeHtml(path, info, findings) {
  const s = summarize(findings);
  const total = findings.length || 1;
  const color = { Critical: 'crit', High: 'high', Medium: 'med', Low: 'low' };
  const parts = [`<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">`,
    `<title>${esc(info.name)} scan report</title><style>${HTML_CSS}</style></head><body><main>`,
    `<h1>${esc(info.name)}: Fortify-like scan</h1>`,
    `<p class="sub">${esc(info.date)} · ${info.files_scanned} files · ${esc(info.engine)} · ${info.rules} rules · ref ${esc(info.ref ?? '')}<br>Not a Fortify scan: the categories, kingdoms and the Fortify Priority Order follow OpenText's public taxonomy and formula; the rules are this tool's, and its dataflow follows a value inside one function, not across files.</p>`,
    '<div class="grid">' + PRIORITIES.map((p) => `<div class="tile"><b style="color:var(--${color[p]})">${s.by_priority[p]}</b><span>${p}</span></div>`).join('') + `<div class="tile"><b>${findings.length}</b><span>issues</span></div></div>`,
    '<div class="bar">' + PRIORITIES.map((p) => `<i class="${p}" style="width:${((100 * s.by_priority[p]) / total).toFixed(1)}%"></i>`).join('') + '</div>'];
  if (info.baseline) parts.push(`<p class="sub">Against the baseline <code>${esc(info.baseline)}</code>: <b>${findings.filter((f) => f.status === 'new').length} new</b>, ${info.baseline_fixed} gone.</p>`);
  parts.push('<h2>Where the issues are</h2><table><tr><th>Part of the tree</th><th class="n">Issues</th></tr>' + Object.entries(s.by_kind).sort().map(([k, v]) => `<tr><td>${esc(k)}</td><td class="n">${v}</td></tr>`).join('') + '</table>');
  parts.push('<h2>Issues by kingdom</h2><table><tr><th>Kingdom</th>' + PRIORITIES.map((p) => `<th class="n">${p}</th>`).join('') + '<th class="n">Total</th></tr>');
  for (const k of KINGDOMS) if (s.by_kingdom[k]) { const c = s.by_kingdom[k]; parts.push(`<tr><td>${esc(k)}</td>` + PRIORITIES.map((p) => `<td class="n">${c[p]}</td>`).join('') + `<td class="n">${sum(c)}</td></tr>`); }
  parts.push('</table><h2>Issues by category</h2><table><tr><th>Category</th><th>Kingdom</th>' + PRIORITIES.map((p) => `<th class="n">${p}</th>`).join('') + '<th class="n">Total</th></tr>');
  for (const [cat, c] of Object.entries(s.by_category).sort((a, b) => sum(b[1]) - sum(a[1]) || a[0].localeCompare(b[0]))) {
    const kingdom = findings.find((f) => f.category === cat).kingdom;
    parts.push(`<tr><td><a href="#${esc(anchor(cat))}">${esc(cat)}</a></td><td>${esc(kingdom)}</td>` + PRIORITIES.map((p) => `<td class="n">${c[p]}</td>`).join('') + `<td class="n">${sum(c)}</td></tr>`);
  }
  parts.push('</table><h2>Issue details</h2>');
  const byCat = new Map();
  for (const f of findings) (byCat.get(f.category) ?? byCat.set(f.category, []).get(f.category)).push(f);
  const cats = [...byCat.entries()].sort((a, b) => Math.min(...a[1].map((f) => order[f.priority])) - Math.min(...b[1].map((f) => order[f.priority])) || b[1].length - a[1].length || a[0].localeCompare(b[0]));
  for (const [cat, items] of cats) {
    const sorted = sortFindings(items);
    const first = sorted[0];
    parts.push(`<h3 id="${esc(anchor(cat))}">${esc(cat)} <span class="tag">${esc(first.kingdom)}</span>` + first.cwe.slice(0, 3).map((c) => `<span class="tag">${esc(c)}</span>`).join('') + '</h3>',
      `<p class="sub">${esc(first.abstract || first.message.split('. ')[0] + '.')}</p>`);
    for (const f of sorted) {
      const tags = `<span class="tag">${esc(f.kind)}</span>` + (f.status === 'new' ? ' <span class="tag new">new</span>' : '') + (f.trace.length ? ' <span class="tag">dataflow</span>' : '');
      parts.push(`<details><summary><span class="p ${f.priority}">${f.priority}</span> <span class="loc">${esc(f.path)}:${f.line}</span>${tags} <small>${esc(f.instance_id.slice(0, 12))}</small></summary><div class="issue"><pre>${esc(f.snippet)}</pre>`);
      if (f.trace.length) parts.push('<div class="trace">' + f.trace.map((st) => `<div><span class="role">${esc(st.role)}</span>L${st.line}: ${esc(st.text.slice(0, 200))}</div>`).join('') + '</div>');
      parts.push(`<p class="msg">${esc(f.message)}</p><p class="sub" style="font-size:12.5px">Impact ${f.impact.toFixed(1)} · Likelihood ${f.likelihood.toFixed(2)} · ${esc(f.engine)} · ${esc(f.rule)}</p></div></details>`);
    }
  }
  parts.push('<h2>Scan information</h2><table>');
  for (const k of ['target', 'ref', 'engine', 'semgrep_version', 'rules', 'files_scanned', 'excludes', 'community', 'errors']) {
    if (k in info) { const v = info[k]; parts.push(`<tr><th>${esc(k.replace(/_/g, ' '))}</th><td>${esc(Array.isArray(v) ? v.join(', ') : String(v))}</td></tr>`); }
  }
  parts.push('</table></main></body></html>');
  writeFileSync(path, parts.join(''));
}

// --- Commands -------------------------------------------------------------------------------------

function ruleFiles() {
  const out = [];
  const walk = (d) => { for (const e of readdirSync(d, { withFileTypes: true })) { const p = join(d, e.name); if (e.isDirectory()) walk(p); else if (e.name.endsWith('.yaml') && !e.name.includes('.test.')) out.push(p); } };
  walk(RULES_DIR);
  return out.sort();
}

function countRules() {
  let n = 0;
  for (const p of ruleFiles()) n += (readFileSync(p, 'utf8').match(/^\s*-\s*id:\s*fortify\./gm) ?? []).length;
  return n + STRUCTURAL.length;
}

export function scan(opts) {
  const target = resolve(opts.target);
  if (!existsSync(target) || !statSync(target).isDirectory()) throw new Error(`not a directory: ${target}`);
  const out = resolve(opts.out ?? 'fortilike-out');
  mkdirSync(out, { recursive: true });
  const name = opts.name ?? basename(target);
  const excludes = [...DEFAULT_EXCLUDES, ...(opts.exclude ?? [])];
  const log = (m) => process.stderr.write(m + '\n');

  const sg = new Semgrep({ engine: opts.semgrep ?? 'docker', image: opts.image ?? SEMGREP_IMAGE, target, excludes, jobs: opts.jobs, scratch: out });
  log(`fortilike ${VERSION}: scanning ${target} (${sg.engine} semgrep)`);
  const configs = [join(RULES_DIR, 'javascript')];
  const { data, prefix } = sg.runJson(configs);
  log(`  rules: ${(data.results ?? []).length} semgrep results`);
  const traces = parseTraces(sg.runTextTraces(configs));
  log(`  traces: ${traces.size} dataflow traces`);
  let { findings, errors } = semgrepResultsToFindings(data, prefix, target, traces, false);
  const filesScanned = (data.paths?.scanned ?? []).length;

  if (opts.community) {
    const c = sg.runJson(COMMUNITY_PACKS);
    const cf = semgrepResultsToFindings(c.data, c.prefix, target, new Map(), true);
    errors = errors.concat(cf.errors);
    const have = new Set(findings.map((f) => `${f.category}|${f.path}|${f.line}`));
    const more = cf.findings.filter((f) => !have.has(`${f.category}|${f.path}|${f.line}`));
    log(`  community: ${more.length} more results after de-duplication`);
    findings = findings.concat(more);
  }
  if (!opts.noStructural) {
    const sf = structuralScan(target, excludes);
    log(`  structural: ${sf.length} results in configuration and text files`);
    findings = findings.concat(sf);
  }
  if (opts.noTests) findings = findings.filter((f) => f.kind !== 'test');

  let baselineFixed = 0;
  if (opts.baseline) {
    try {
      const base = JSON.parse(readFileSync(opts.baseline, 'utf8'));
      const known = new Set((base.findings ?? []).map((f) => f.instance_id));
      for (const f of findings) f.status = known.has(f.instance_id) ? 'existing' : 'new';
      const now = new Set(findings.map((f) => f.instance_id));
      baselineFixed = [...known].filter((id) => !now.has(id)).length;
    } catch (err) {
      log(`  baseline unreadable: ${err.message}`);
    }
  }

  findings = sortFindings(findings);
  const info = {
    name, target, ref: opts.ref ?? '', date: new Date().toISOString().slice(0, 16).replace('T', ' '),
    engine: `Semgrep CE (${sg.engine})`, semgrep_version: sg.version(), rules: countRules(), files_scanned: filesScanned,
    excludes, community: Boolean(opts.community), baseline: opts.baseline ?? '', baseline_fixed: baselineFixed, errors: errors.slice(0, 10),
  };
  writeJson(join(out, 'fortilike.json'), info, findings);
  writeSarif(join(out, 'fortilike.sarif'), info, findings);
  writeMarkdown(join(out, 'report.md'), info, findings);
  writeHtml(join(out, 'report.html'), info, findings);
  const s = summarize(findings);
  log(`  ${findings.length} issues: ` + PRIORITIES.map((p) => `${s.by_priority[p]} ${p}`).join(', '));
  log(`  wrote ${out}/report.html, report.md, fortilike.json, fortilike.sarif`);
  if (opts.failOn) {
    const worst = order[opts.failOn];
    const bad = findings.filter((f) => order[f.priority] <= worst && f.kind === 'production' && (!opts.baseline || f.status === 'new'));
    if (bad.length) { log(`  ${bad.length} ${opts.failOn}-or-worse production issues`); return 1; }
  }
  return 0;
}

export function testRules(opts) {
  const engine = opts.semgrep ?? 'docker';
  const image = opts.image ?? SEMGREP_IMAGE;
  const r = engine === 'docker'
    ? spawnSync('docker', ['run', '--rm', '-v', `${RULES_DIR}:/src:ro`, '-w', '/src', image, 'semgrep', '--test', '--metrics=off', '/src/javascript'], { stdio: 'inherit' })
    : spawnSync('semgrep', ['--test', '--metrics=off', join(RULES_DIR, 'javascript')], { stdio: 'inherit' });
  return r.status ?? 1;
}

export function listRules() {
  const rows = [];
  for (const p of ruleFiles()) {
    const text = readFileSync(p, 'utf8');
    for (const block of text.split(/^\s*-\s*id:\s*/m).slice(1)) {
      const rid = block.split('\n')[0].trim();
      const g = (re) => re.exec(block)?.[1];
      const cat = g(/category:\s*"?([^"\n]+)"?/);
      const nums = ['impact', 'probability', 'accuracy', 'confidence'].map((k) => Number(g(new RegExp(`${k}:\\s*"?([\\d.]+)`))));
      const pr = nums.every((n) => !Number.isNaN(n)) ? fortifyPriority(...nums)[0] : '?';
      rows.push([rid, cat?.trim() ?? '?', block.includes('mode: taint') ? 'dataflow' : 'structural', pr]);
    }
  }
  for (const r of STRUCTURAL) { const d = categoryDefaults(r.category); rows.push([r.id, r.category, 'configuration', fortifyPriority(d.impact, d.probability, d.accuracy, r.confidence)[0]]); }
  const width = Math.max(...rows.map((r) => r[0].length));
  for (const [rid, cat, kind, pr] of rows) process.stdout.write(`${rid.padEnd(width)}  ${pr.padEnd(8)} ${kind.padEnd(13)} ${cat}\n`);
  process.stderr.write(`\n${rows.length} rules\n`);
  return 0;
}

const USAGE = `fortilike ${VERSION}: a Fortify-like static analysis for JavaScript and TypeScript.

  fortilike scan <dir> [--out DIR] [--name NAME] [--ref REF] [--exclude GLOB]... [--baseline JSON]
                       [--community] [--no-structural] [--no-tests] [--semgrep docker|local]
                       [--image IMAGE] [--jobs N] [--fail-on Critical|High|Medium|Low]
  fortilike test-rules [--semgrep docker|local] [--image IMAGE]
  fortilike list-rules

Output: report.html, report.md, fortilike.json (baselines), fortilike.sarif. Not Fortify: the categories,
kingdoms and the Fortify Priority Order follow OpenText's public taxonomy; the rules are this tool's.
`;

export function main(argv) {
  const [command, ...rest] = argv;
  const opts = { exclude: [] };
  const positional = [];
  for (let i = 0; i < rest.length; i++) {
    const a = rest[i];
    const take = () => { const v = rest[++i]; if (v === undefined) throw new Error(`${a} needs a value`); return v; };
    if (a === '--out') opts.out = take();
    else if (a === '--name') opts.name = take();
    else if (a === '--ref') opts.ref = take();
    else if (a === '--exclude') opts.exclude.push(take());
    else if (a === '--baseline') opts.baseline = take();
    else if (a === '--community') opts.community = true;
    else if (a === '--no-structural') opts.noStructural = true;
    else if (a === '--no-tests') opts.noTests = true;
    else if (a === '--semgrep') opts.semgrep = take();
    else if (a === '--image') opts.image = take();
    else if (a === '--jobs') opts.jobs = Number(take());
    else if (a === '--fail-on') opts.failOn = take();
    else if (a === '-h' || a === '--help') { process.stdout.write(USAGE); return 0; }
    else if (a.startsWith('-')) throw new Error(`unknown option ${a}`);
    else positional.push(a);
  }
  if (opts.semgrep && !['docker', 'local'].includes(opts.semgrep)) throw new Error('--semgrep takes docker or local');
  if (opts.failOn && !PRIORITIES.includes(opts.failOn)) throw new Error(`--fail-on takes one of ${PRIORITIES.join(', ')}`);
  switch (command) {
    case 'scan':
      if (!positional[0]) throw new Error('usage: fortilike scan <dir>');
      return scan({ ...opts, target: positional[0] });
    case 'test-rules':
      return testRules(opts);
    case 'list-rules':
      return listRules();
    case undefined:
    case '-h':
    case '--help':
      process.stdout.write(USAGE);
      return command ? 0 : 2;
    case '--version':
      process.stdout.write(VERSION + '\n');
      return 0;
    default:
      throw new Error(`unknown command ${command}\n\n${USAGE}`);
  }
}
