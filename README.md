# fortilike

A Fortify-like static analysis for JavaScript and TypeScript, as an npm command: the same
categories, kingdoms and priority order as OpenText SAST (Fortify Static Code Analyzer), dataflow
findings with a source-to-sink trace, and a Developer-Workbook-style report. Built so a team can fix
and explain its findings before the licensed scan runs, and keep the number the security team sees
small.

It is **not Fortify**. OpenText's Secure Coding Rulepacks are licensed and cannot be reproduced. What
this tool reproduces is the *shape* of a Fortify scan:

| Fortify | fortilike |
| --- | --- |
| Categories such as *Path Manipulation*, *Cross-Site Scripting: DOM*, *Password Management: Hardcoded Password*, grouped in the Seven Pernicious Kingdoms | the same names and kingdoms (`taxonomy/categories.json`): all 114 JavaScript/TypeScript categories of rulepack 26.4, plus the JSON, YAML and universal ones that apply to a Node repository (`taxonomy/fortify-26.4-languages.json`, read from vulncat.fortify.com) |
| What is scanned: the repository the pipeline checks out | the files git knows (tracked, or untracked and not ignored); `--all-files` reads the whole tree |
| Fortify Priority Order: Critical / High / Medium / Low from Impact and Likelihood (Accuracy × Confidence × Probability ÷ 25) | the same formula; each rule carries its Impact, Probability, Accuracy and Confidence |
| Global dataflow analysis: a source (a request, the command line, the environment, a database row, an error, a value named like a secret, the page's URL, Web Storage) reaches a sink across functions and files, one issue per source and sink pair, with the trace shown | the same, on the TypeScript compiler's type checker (`src/dataflow.mjs`): calls resolve to their declarations, interface calls to every implementation, NestJS parameter decorators and Fastify, Express and Node `http` handlers bind request data |
| Structural rules on the code's shape (credentials in code, weak crypto, TLS checks off, cookies, empty catch blocks, check-then-act) | Semgrep pattern rules |
| Rules for configuration (credentials in config, `.env` files, `.npmrc`, `package.json`, compose files, JSON data, Dockerfiles, pipelines) and OpenAPI descriptions | a built-in layer for files Semgrep does not read as code, and `src/openapi.mjs` for the *OpenAPI Misconfiguration* family |
| *Password Management: Password in Comment* on any comment that names a password, secret or key, with or without a value | the same, in code, configuration, scripts and Dockerfiles |
| Audit Workbench / the Developer Workbook report, Instance IDs that survive line moves | `report.html`, `report.md`, `fortilike.json` and SARIF, with a stable instance id per finding and `--baseline` to mark what is new |

What still differs: the rules are this tool's, written from Fortify's public category descriptions,
not OpenText's rulepacks, so a count will be close to the licensed scan's rather than equal. The
dataflow is field-sensitive one object level deep (data put under `password` stays there when
`role` is read) and flow-insensitive, which over-reports the way Fortify does. Without TypeScript in
the scanned project (or next to fortilike), `--dataflow semgrep` is used: Semgrep's taint mode, which
follows a value inside one function only.

## Install and run

Needs Node 20.19+ and Docker (Semgrep runs from a pinned image), or a local `semgrep`. The global
dataflow uses the scanned project's own `typescript` package, or fortilike's optional dependency on it.

```sh
npm install -g github:mohamedyousef/fortilike     # or: git clone … && npm install -g ./fortilike
fortilike scan ../minikit_js --name minikit_js --ref dev --out out/minikit_js
```

Without installing, from a checkout: `node bin/fortilike scan <dir>` or `npx --prefix . fortilike`.

```sh
fortilike scan <dir> --exclude packages/cli/simulator/web --no-tests
fortilike scan <dir> --all-files                               # also files git ignores or does not know
fortilike scan <dir> --dataflow semgrep                        # one-function taint rules instead of global dataflow
fortilike scan <dir> --baseline out/minikit_js/fortilike.json   # marks new and gone issues
fortilike scan <dir> --community                               # + Semgrep's registry packs, mapped to Fortify categories by CWE
fortilike scan <dir> --fail-on High                            # exit 1 on a High or Critical production issue
fortilike scan <dir> --semgrep local                           # a local semgrep instead of Docker
fortilike list-rules
fortilike test-rules                                           # the Semgrep rule fixtures (100 cases)
npm test                                                       # those, plus the dataflow, configuration and OpenAPI fixtures
```

Output in `--out` (default `./fortilike-out`): `report.html` (open it), `report.md`, `fortilike.json`
(every finding with its trace, for baselines), `fortilike.sarif` (for GitHub code scanning or any
SARIF viewer). `--exclude` adds names or path globs; `node_modules`, `dist`, `build`, `coverage`,
build caches and `*.min.js` are skipped by default.

Findings are tagged by where they sit: `production`, `test`, `example`, `template`, `tooling`,
`docs`, `ci`, `config`. Fortify scans what the repository holds, so tests count; `--no-tests` drops
them from the report when the licensed scan will exclude them. Semgrep's built-in ignore list would
skip `test/` folders in a repository that has no `.semgrepignore`; the tool supplies a neutral one
so the tests are read either way.

## Rules

`rules/javascript/*.yaml`, Semgrep syntax, each with `metadata.fortify` (category, kingdom, impact,
probability, accuracy, confidence, abstract) and CWE / OWASP references. Every rule file has a
fixture (`*.test.ts`, `*.test.tsx`) with `// ruleid:` and `// ok:` lines; `fortilike test-rules`
runs them. 101 Semgrep rules (23 of them taint rules, used only with `--dataflow semgrep`), 14
configuration rules, the OpenAPI rules and the global dataflow engine's sinks.

**Dataflow** (the global engine, or Semgrep taint mode with `--dataflow semgrep`): Path Manipulation · Path Manipulation: Zip Entry Overwrite · Command
Injection · Server-Side Request Forgery · Open Redirect · Header Manipulation · Header Manipulation:
Cookies · Cross-Site Scripting: Reflected · Cross-Site Scripting: DOM · Log Forging · Denial of
Service: Regular Expression · Dynamic Code Evaluation: Code Injection · Dynamic Code Evaluation:
Unsafe Deserialization · SQL Injection · NoSQL Injection · Resource Injection · Setting Manipulation ·
Prototype Pollution · Mass Assignment · Dangerous File Inclusion · Server-Side Template Injection ·
Access Control: Database · Trust Boundary Violation.

Sources: `request.url`, `.headers`, `.query`, `.params`, `.body`, `.cookies` (Node and Express names,
and any `IncomingMessage`-typed parameter), `process.argv`, `process.env` (for commands),
`location.*`, `document.URL` / `.referrer` / `.cookie`, `window.name`, `event.data` in a message
handler, archive entry names. Sanitizers: `basename`, `Number`, `String` (NoSQL), `ObjectId`,
`encodeURIComponent`, `JSON.stringify`, functions named escape / sanitize / encode / purify / validate,
`DOMPurify`, `createTextNode`.

**Structural**: Password Management: Hardcoded Password / Empty Password / Null Password / Weak
Cryptography · Credential Management: Hardcoded API Credentials · Key Management: Hardcoded Encryption
Key / Empty Encryption Key · Insecure Randomness · Weak Cryptographic Hash (+ Hardcoded Salt) · Weak
Encryption (+ Insecure Mode of Operation, Insufficient Key Size, Inadequate RSA Padding) · Insecure SSL:
Server Identity Verification Disabled · Insecure Transport (+ Weak SSL Protocol) · Cookie Security:
HTTPOnly not Set / Cookie not Sent Over SSL / Persistent Cookie · Privacy Violation (+ Autocomplete) ·
JSON Web Token: Missing Signature Check · HTML5: Overly Permissive Message Posting Policy / CORS
Policy / Content Security Policy · Cross-Frame Scripting · Cross-Site Request Forgery · XML External
Entity Injection · Often Misused: File Upload · Denial of Service (request bodies, nested quantifiers) ·
Race Condition: File System Access · Insecure Temporary File · Poor Error Handling: Empty Catch
Block · System Information Leak: External / Internal.

**Rulepack 26.x additions** (`fortify-26.yaml`): Cookie Security: Missing SameSite Attribute / Overly
Permissive SameSite Attribute / Overly Broad Domain / Overly Broad Path · Dynamic Code Evaluation:
Unsafe YAML Deserialization / Script Injection · GraphQL Bad Practices: GraphiQL Enabled /
Introspection Enabled · Handlebars Misconfiguration: Escaping Disabled / Prototypes Allowed · Helmet
Misconfiguration: Insecure XSS Filter · HTML5: Cross-Site Scripting Protection / Deprecated Header /
MIME Sniffing / Easy-to-Guess Database Name · Insecure Transport: HSTS not Set / Weak SSL Cipher /
Insufficient Diffie Hellman Strength · Key Management: Hardcoded HMAC Key / Empty HMAC Key /
Hardcoded PBE Password / Empty PBE Password / Null Encryption Key · Weak Cryptographic Hash: Empty PBE
Salt / Insecure PBE Iteration Count / Predictable Salt · Weak Encryption: Insecure Initialization
Vector / Stream Cipher / Non PQC Resilient Algorithm · Poor Logging Practice: Use of a System Output
Stream · React Bad Practices: Dangerously Set InnerHTML · Code Correctness: Negative Content-Length ·
LLM Misconfiguration: Unspecified Token Limit · Cross-Site Scripting: SOP Bypass / Poor Validation ·
Setting Manipulation: User-Controlled Allow List · DNS Spoofing. Cross-Session Contamination (a
request handler writing module-level state) is in the global engine.

**Configuration** (`src/fortilike.mjs`, `STRUCTURAL`): Password Management: Password in Configuration
File (also compose `environment:` entries) / Password in Comment (any comment naming a password,
secret or key, in code, `.env`, YAML, scripts and Dockerfiles, as Fortify reports it) · credential
keys with values in JSON files · npm tokens in `.npmrc` · credentials in URLs · PEM keys in any text
file · Dockerfile Misconfiguration (no `USER`) · Build Misconfiguration (`curl | sh`, actions pinned by
tag, install scripts that download and run code) · Insecure Transport (`strict-ssl=false`, http
addresses in configuration, `http://` and `git://` dependencies in `package.json`).

**OpenAPI** (`src/openapi.mjs`): OpenAPI Misconfiguration: Missing Security Schemes / Weak
Authentication / Credential Leakage / Missing, Empty or Optional Global and Operation Security
Requirement / Missing Error Handling / Insecure Transport.

### Adding a rule

Copy a rule in the matching `rules/javascript/*.yaml`, give it a Fortify category and kingdom (add
the category to `taxonomy/categories.json` if it is new), set Impact / Probability / Accuracy /
Confidence, add `// ruleid:` and `// ok:` lines to the fixture, and run `fortilike test-rules`.
Semgrep rules to remember: an annotation applies to the very next line only; a `metavariable-regex`
on a metavariable that an alternative does not bind makes that alternative fail, so keep such
alternatives in their own `patterns` block; single-line patterns that contain `: ` must be quoted;
metadata numbers are strings.

### Global dataflow

`src/dataflow-spec.mjs` lists what the engine treats as sources, sinks and sanitizers, and which
category each source kind produces at each sink:

| Source kind | Examples | Categories it can produce |
| --- | --- | --- |
| web | `request.query`, `.body`, `.params`, `.headers`, `.url`, `.ip`; `@Query()`, `@Body()`, `@Param()`, `@Headers()` | every injection category, Header Manipulation, Open Redirect, Access Control: Database, Mass Assignment, Prototype Pollution, Log Forging |
| argv, env, file | `process.argv`, `process.env`, `readFile` results | Command Injection, Path Manipulation, SSRF, Resource Injection, Setting Manipulation |
| database | Kysely, `pg`, ORM, Redis and S3 reads | Cross-Site Scripting: Persistent, Header Manipulation, Prompt Injection: Persistent |
| error | `catch (err)`, `.catch(err => …)`, error handlers, `err.stack` | System Information Leak: External (response), System Information Leak: Internal (log) |
| privacy | values named password, secret, token, key, ssn… whose type can hold one | Privacy Violation (log, response, file, cookie, URL, Web Storage) |
| dom, storage, network | `location.*`, `document.referrer`, `event.data`, `localStorage`, `fetch` bodies in browser code | Cross-Site Scripting: DOM, Open Redirect, Script Injection, Trust Boundary Violation |

`test/dataflow/fixture` holds one case per shape with `// df-ruleid:` and `// df-ok:` lines;
`npm run test:dataflow` checks them.

## Priority

```
likelihood = accuracy × confidence × probability / 25
Critical: impact ≥ 2.5 and likelihood ≥ 2.5      High:   impact ≥ 2.5 and likelihood < 2.5
Medium:   impact < 2.5 and likelihood ≥ 2.5      Low:    both below 2.5
```

Dataflow rules carry confidence 5 (a full trace), API-shape rules 4 to 5, literal and heuristic rules
3 to 4. The numbers are this tool's calibration, set so each category lands where Fortify usually
files it; they are not OpenText's.

## Layout

```
bin/fortilike             the command
src/fortilike.mjs         runs Semgrep on the files git knows, the global dataflow, the configuration
                          layer and the OpenAPI rules; priorities, reports
src/dataflow.mjs          global dataflow on the TypeScript compiler API
src/dataflow-spec.mjs     its sources, sinks, sanitizers and category table
src/openapi.mjs           OpenAPI Misconfiguration rules over openapi.yaml / openapi.json
test/                     the dataflow fixture and its test
rules/javascript/         the rule pack and its fixtures
taxonomy/categories.json  categories -> kingdom, CWE, Impact/Probability/Accuracy/Confidence; CWE -> category
taxonomy/fortify-26.4-languages.json  Fortify's category names per language, rulepack 26.4
```
