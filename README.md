# fortilike

A Fortify-like static analysis for JavaScript and TypeScript repositories: the same categories,
kingdoms and priority order as OpenText SAST (Fortify Static Code Analyzer), dataflow findings with a
source-to-sink trace, and a Developer-Workbook-style report. Built so a team can fix and explain its
findings before the licensed scan runs, and keep the number the security team sees small.

It is **not Fortify**. OpenText's Secure Coding Rulepacks are licensed and cannot be reproduced. What
this tool reproduces is the *shape* of a Fortify scan:

| Fortify | fortilike |
| --- | --- |
| Categories such as *Path Manipulation*, *Cross-Site Scripting: DOM*, *Password Management: Hardcoded Password*, grouped in the Seven Pernicious Kingdoms | the same names and kingdoms (`taxonomy/categories.json`) |
| Fortify Priority Order: Critical / High / Medium / Low from Impact and Likelihood (Accuracy × Confidence × Probability ÷ 25) | the same formula; each rule carries its Impact, Probability, Accuracy and Confidence |
| Dataflow analysis: a source (a request, the command line, the page's URL, a posted message) reaches a sink without a sanitizer, with the trace shown | Semgrep's taint mode with this tool's sources, sinks and sanitizers; the trace from source to sink is in the report |
| Structural rules on the code's shape (credentials in code, weak crypto, TLS checks off, cookies, empty catch blocks, check-then-act) | Semgrep pattern rules |
| Rules for configuration (credentials in config, Dockerfiles, pipelines) | a built-in layer for files Semgrep does not read as code |
| Audit Workbench / the Developer Workbook report, Instance IDs that survive line moves | `report.html`, `report.md`, `fortilike.json` and SARIF, with a stable instance id per finding and `--baseline` to mark what is new |

The one real difference: Fortify's dataflow follows a value across functions and files. Semgrep's
open engine follows it inside one function, so a value that arrives as a parameter is not followed
(a helper that takes `path` from its caller is not reported; the caller that reads `request.url`
and opens the file is). Findings that need that cross-function view come from the licensed scan.

## Run

Needs Python 3.11+ and Docker (Semgrep runs from a pinned image), or a local `semgrep`.

```sh
bin/fortilike scan ../minikit_js --name minikit_js --ref dev --out out/minikit_js
bin/fortilike scan ../minikit_js --exclude packages/cli/simulator/web --no-tests
bin/fortilike scan ../minikit_js --baseline out/minikit_js/fortilike.json   # marks new and gone issues
bin/fortilike scan ../minikit_js --community                                  # + Semgrep's registry packs, mapped to Fortify categories by CWE
bin/fortilike scan ../minikit_js --fail-on High                               # exit 1 on a High or Critical production issue
bin/fortilike list-rules
bin/fortilike test-rules                                                      # the rule fixtures (38 cases)
```

Output in `--out` (default `./fortilike-out`): `report.html` (open it), `report.md`, `fortilike.json`
(every finding with its trace, for baselines), `fortilike.sarif` (for GitHub code scanning or any
SARIF viewer). The scan honours the target's `.semgrepignore`; `--exclude` adds names or paths.

Findings are tagged by where they sit: `production`, `test`, `example`, `template`, `docs`, `ci`,
`config`. Fortify scans what the repository holds, so tests count; `--no-tests` drops them from the
report when the licensed scan will exclude them.

## Rules

`rules/javascript/*.yaml`, Semgrep syntax, each with `metadata.fortify` (category, kingdom, impact,
probability, accuracy, confidence, abstract) and CWE / OWASP references. Every rule file has a
fixture (`*.test.ts`, `*.test.tsx`) with `// ruleid:` and `// ok:` lines; `bin/fortilike test-rules`
runs them.

**Dataflow (taint mode)**: Path Manipulation · Command Injection · Server-Side Request Forgery ·
Open Redirect · Header Manipulation · Cross-Site Scripting: Reflected · Cross-Site Scripting: DOM ·
Log Forging · Denial of Service: Regular Expression · Dynamic Code Evaluation: Code Injection ·
SQL Injection · Resource Injection · Setting Manipulation.

Sources: `request.url`, `.headers`, `.query`, `.params`, `.body`, `.cookies` (Node and Express names,
and any `IncomingMessage`-typed parameter), `process.argv`, `process.env` (for commands),
`location.*`, `document.URL` / `.referrer` / `.cookie`, `window.name`, `event.data` in a message
handler. Sanitizers: `basename`, `Number`, `encodeURIComponent`, `JSON.stringify`, functions named
escape / sanitize / encode / purify, `DOMPurify`, `createTextNode`.

**Structural**: Password Management: Hardcoded Password / Empty Password · Key Management: Hardcoded
Encryption Key (crypto APIs with literal keys, PEM private keys) · Insecure Randomness · Weak
Cryptographic Hash · Weak Encryption (+ Insecure Mode of Operation, Insufficient Key Size,
Inadequate RSA Padding) · Insecure SSL: Server Identity Verification Disabled · Insecure Transport ·
Cookie Security: HTTPOnly not Set / Cookie not Sent Over SSL · Privacy Violation (+ Autocomplete) ·
HTML5: Overly Permissive Message Posting Policy / CORS Policy / Content Security Policy · Race
Condition: File System Access · Insecure Temporary File · Poor Error Handling: Empty Catch Block ·
System Information Leak: External / Internal.

**Configuration** (`fortilike.py`, `STRUCTURAL`): Password Management: Password in Configuration
File / Password in Comment · credentials in URLs · PEM keys in any text file · Dockerfile
Misconfiguration (no `USER`) · Build Misconfiguration (`curl | sh`, actions pinned by tag) ·
Insecure Transport (`strict-ssl=false`, http addresses in configuration).

### Adding a rule

Copy a rule in the matching `rules/javascript/*.yaml`, give it a Fortify category and kingdom (add
the category to `taxonomy/categories.json` if it is new), set Impact / Probability / Accuracy /
Confidence, add `// ruleid:` and `// ok:` lines to the fixture, and run `bin/fortilike test-rules`.
Two Semgrep rules to remember: an annotation applies to the very next line only, and a
`metavariable-regex` on a metavariable that an alternative does not bind makes that alternative
fail, so keep such alternatives in their own `patterns` block.

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
fortilike.py           the tool: runs Semgrep (JSON for results, text for the taint traces, which
                       Semgrep CE prints only there), the configuration layer, priorities, reports
bin/fortilike          launcher
rules/javascript/      the rule pack and its fixtures
taxonomy/categories.json  categories -> kingdom, CWE, Impact/Probability/Accuracy/Confidence; CWE -> category for community rules
```
