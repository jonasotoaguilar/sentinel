# Code Rules Specification

## Purpose

Detects vulnerability patterns in JavaScript/TypeScript and Python source that
are expressible on a syntax tree but not on a single line, and reports them
through the existing normalized finding model.

## Requirements

### Requirement: Language detection by extension

The engine MUST select a grammar by file extension, case-insensitively:
JavaScript/TypeScript for `js`, `mjs`, `cjs`, `jsx`, `ts`, `mts`, `cts`, `tsx`,
and Python for `py`, `pyi`. A file whose extension is not listed MUST be
skipped silently — no finding, no diagnostic, no parse attempt. A path with no
extension MUST be skipped the same way.

#### Scenario: Supported extensions are parsed

- GIVEN files `a.js`, `b.mjs`, `c.cjs`, `d.jsx`, `e.ts`, `f.mts`, `g.cts`,
  `h.tsx`, `i.py`, `j.pyi`, each containing one violating construct
- WHEN `sentinel scan` runs
- THEN each file produces its rule finding

#### Scenario: Unsupported files are skipped silently

- GIVEN `main.rs`, `README.md`, `Makefile` and `script` (no extension), one of
  them containing text that would match a rule pattern
- WHEN `sentinel scan` runs
- THEN no `rules` finding and no diagnostic is emitted for them

#### Scenario: Extension case is ignored

- GIVEN `A.JS` containing a violating construct
- WHEN `sentinel scan` runs
- THEN the finding is emitted

### Requirement: Pinned rule set with stable rule ids

The engine MUST implement exactly these rules, with these ids and severities;
ids MUST be stable across releases (a rename keeps the old id resolvable the
way `deprecated_ids` does for secrets). Engine id MUST be `rules`.

| Rule id | Language | Construct | CWE | Severity |
| ------- | -------- | --------- | --- | -------- |
| `RULE-weak-hash` | js/ts | `crypto.createHash(<string literal 'md5' or 'sha1'>)` | 327 | Medium |
| `RULE-dynamic-code` | js/ts | `eval(<non-literal>)`; `new Function(<non-literal body>)` | 95 | Critical |
| `RULE-shell-injection` | js/ts | `child_process.exec`/`execSync` whose command argument is a template literal containing an interpolation, or a `+` expression | 78 | Critical |
| `RULE-weak-hash-python` | py | `hashlib.md5(...)` / `hashlib.sha1(...)` | 327 | Medium |
| `RULE-shell-injection-python` | py | `subprocess.<fn>(..., shell=True, ...)` | 78 | Critical |
| `RULE-unsafe-deserialization-python` | py | `pickle.load(`/`pickle.loads(` with any arguments; `yaml.load(__)` with no `Loader=` argument | 502 | High |

Matching is name-based over the syntax tree with no type or import resolution;
that limitation is part of the contract, not a defect.

#### Scenario: Every rule fires with its pinned id and severity

- GIVEN one fixture per rule containing exactly one violating construct
- WHEN `sentinel scan` runs
- THEN each finding carries its pinned `rule_id`, `engine="rules"`, and its
  pinned severity

### Requirement: AST-required non-findings

Constructs whose argument is a compile-time literal MUST NOT be reported. This
is the reason these rules are AST rules: the textual form alone cannot decide.

#### Scenario: Literal arguments are clean

- GIVEN `eval("print(1)")`, `new Function("return 1")`,
  `crypto.createHash("sha256")`, `subprocess.run(cmd, shell=False)`,
  `yaml.load(data, Loader=yaml.SafeLoader)`, `yaml.safe_load(data)` and
  `hashlib.sha256(data)`
- WHEN `sentinel scan` runs
- THEN none of them produces a `rules` finding

#### Scenario: A bare identifier is not a shell-injection finding

- GIVEN `child_process.exec(cmd)` where `cmd` is a plain identifier
- WHEN `sentinel scan` runs
- THEN no finding is emitted (only an interpolated or concatenated command is
  reported)

### Requirement: Redaction at the engine boundary

Every finding the engine emits MUST pass through the shared redaction pass
before it leaves the engine: the snippet and evidence MUST have every
occurrence of a value matching a secrets rule replaced by `[REDACTED]`, and the
fingerprint digest MUST be computed over the matched construct before
redaction. Raw values MUST NOT appear in findings, diagnostics, report bytes,
or logs.

#### Scenario: A secret inside a matched construct is redacted

- GIVEN ``exec("curl -H 'Authorization: Bearer sk-synthetic-1234567890' " + url)``
- WHEN `sentinel scan` runs
- THEN a `RULE-shell-injection` finding emits, and no output, diagnostic or
  report byte contains `sk-synthetic-1234567890`

### Requirement: Parse-failure degradation

A file the grammar cannot fully parse MUST NOT be silently dropped and MUST NOT
produce findings: the engine MUST emit exactly one `rule-fallback` diagnostic
naming the path and MUST report no rule finding for that file. Degradation is
per file: every other file is scanned normally, and a file whose syntax is
repaired is covered again with no change to the engine.

#### Scenario: Unparseable file warns once and reports nothing

- GIVEN a JavaScript file that does not parse and contains
  `crypto.createHash('md5')`
- WHEN `sentinel scan` runs
- THEN no `rules` finding is emitted for that file, exactly one `rule-fallback`
  diagnostic names the path, and the exit code is 0 when no other file reports a
  finding (never 2)

#### Scenario: The parseable twin is still scanned

- GIVEN the same file with its syntax error repaired
- WHEN `sentinel scan` runs
- THEN the `RULE-weak-hash` finding emits and no `rule-fallback` diagnostic is
  emitted

### Requirement: Deterministic, contained engine

Identical input MUST produce byte-identical output including rule and diagnostic
order, independent of file parallelism. A rule that cannot be compiled or
applied MUST emit one `rule-failed` diagnostic and MUST NOT prevent the
remaining rules or engines from running; the exit code MUST stay 0 or 1.

#### Scenario: Two runs are byte-identical

- GIVEN a fixture tree with several violating files
- WHEN `sentinel scan --output json` runs twice
- THEN both runs produce identical bytes

#### Scenario: A failing rule is contained

- GIVEN an engine whose one rule cannot compile
- WHEN a scan runs
- THEN the other rules still report and one `rule-failed` diagnostic names the
  failing rule on stderr
