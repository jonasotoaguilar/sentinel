# Design: Sentinel Code Rules Engine

## Context

`sentinel` already runs two engines (`secrets` regex table, `dependency` OSV)
through one pipeline: discovery → per-file parallelism → engine candidates →
`normalize` dedupe/sort → renderer. `normalize::to_findings` currently hardcodes
the secrets engine id, and `secrets::Candidate` already carries every field the
finding model needs. The new engine is additive and must not perturb the two
shipped engines, their fingerprints, or the renderers.

## Decisions

### D1 — Reuse `Candidate`, parameterize normalization

`rules::scan` returns `Vec<secrets::Candidate>`. Normalization gains a
`to_findings_for(engine, path, candidates)` seam; the existing `to_findings`
becomes a one-line wrapper for the secrets engine, so no existing fingerprint or
test changes. Rejected: a parallel `RulesCandidate` type plus a second
conversion path (duplicated fingerprint logic, no second consumer).

### D2 — Grammars

`tree-sitter` 0.27 with `tree-sitter-javascript` 0.25,
`tree-sitter-typescript` 0.23 and `tree-sitter-python` 0.25. Each grammar
exposes `LANGUAGE: LanguageFn`, converted once per language via
`Language::from`. The three grammars are held in a lazily initialized static so
compilation happens at most once per process and parallel file scans share it.
Rejected: loading grammars per file (repeat cost) and per-language engine
instances (splits one engine across three ids, changing fingerprints).

### D3 — Direct node matching, no query files

Rules walk the tree and match node kinds plus their child text. A `.scm` query
file would be a shipped runtime artifact to package and version, and its
evaluation errors would need a second failure path; with six rules the direct
form is smaller and keeps the failure surface to `rule-failed`.

The TypeScript grammar has two root variants (`typescript`, `tsx`); `.tsx` maps
to the TSX variant and every other `ts`-family extension to the TypeScript one.

### D4 — Which argument shapes count as "non-literal"

A rule that needs the AST to decide treats an argument as literal only when it
is a `string` node, or a `template_string` with no `template_substitution`
child. Everything else is non-literal and reported. This is what makes
`eval("print(1)")` clean and `eval(userInput)` a finding, and it is the whole
reason the rule set cannot be expressed as regexes.

### D5 — Shell-injection scope is interpolation or concatenation

`exec`/`execSync` is reported only when the command argument is a
`template_string` with at least one `template_substitution`, or a
`binary_expression` using `+`. A bare identifier is deliberately not reported:
without dataflow it cannot be distinguished from a constant, and a rule that
fires on `exec(cmd)` would be noise in every real repository. Python's
counterpart is exact instead of heuristic (`shell=True` is a literal keyword),
which is why `RULE-shell-injection-python` has no such narrowing.

### D6 — An unparseable file is skipped, and said so

Two mechanisms were written and both were removed for one reason. A conservative
regex table matched a construct inside a comment or a string literal, because no
pattern can tell text from the same text in a comment. Restricting the AST
matchers to the regions the parser recovered then matched text the parser had
promoted to code while recovering from an unterminated delimiter: a file
containing `s = "subprocess.run(cmd, shell=True)` with no closing quote yields a
clean-looking call node for the text inside the broken string, which the
parseable twin reports nothing for.

Neither can honour the requirement, because a parse failure means the parser does
not know what the text was meant to be, and every recovery is a guess about
intent. The engine therefore reports the diagnostic and no finding for that
file: the invariant holds by construction, the operator is told which file was
not analysed, and coverage returns the moment the syntax is repaired. The trade
is deliberate and is the one a security scanner has to make — a claim the engine
cannot stand behind is worse than a disclosed gap, and the file was already
failing to parse in whatever else reads it.

### D7 — Redaction seam

`SecretsEngine` gains `redact(&self, text: &str) -> String`, applying its
compiled table to arbitrary text. The rules engine passes its matched construct
through it and stores the result as `snippet`/`evidence`; the digest is computed
over the pre-redaction construct, exactly as the secrets engine does. This keeps
one redaction implementation and satisfies the PRD's "redacted at the engine
boundary" rule without a new module.

### D8 — Diagnostic code

One new constructor, `Diagnostic::rule_fallback(path, message)`, code
`rule-fallback`, rendered like the others on stderr and never inside report
bytes. The name is kept although the engine no longer falls back to a second
mechanism: it reports that a file's coverage fell back to nothing, which is what
the code means to an operator reading it. The existing `rule-failed` covers rule
compilation/application failure.

## Threat matrix

| Threat | Mitigation | Alternative rejected |
| ------ | ---------- | -------------------- |
| Catastrophic backtracking or a pathological tree walk on hostile source | Bounded per-file byte cap inherited from discovery; direct node walk with no recursion into unrelated subtrees | Unbounded regex on whole-file text |
| A crafted file making the parser emit an error tree and the fallback over-report | Unparseable files produce no findings at all, so there is nothing to over-report; the single `rule-fallback` diagnostic discloses the gap | Treating every error file as fully trusted |
| Secret material in a matched source line reaching a report | D7 shared redaction pass, asserted by an integration test that greps every output stream | Per-engine ad-hoc redaction |
| One bad rule killing the scan | Per-rule compile failure → `rule-failed`, remaining rules run | Panic or early return |
| Non-determinism from parallel parsing | Findings collected per file in discovery order and sorted by the existing `dedupe_and_sort` | Sorting inside the engine |

## Test strategy

RED first, one test per spec rule: language detection (positive and
skipped-silently), each rule's id/severity, each literal non-finding, the bare
identifier non-finding, redaction with a secret embedded in a matched line,
parse-failure degradation in both directions, `rule-failed` containment, and a
two-run byte-identical comparison through the binary in `tests/rules.rs`.
