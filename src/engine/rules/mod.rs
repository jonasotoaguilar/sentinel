//! Code-rules engine (PR1 skeleton plus the JavaScript/TypeScript rule set);
//! Python rules arrive as further entries in the rule table.

pub mod javascript;
pub mod lang;
pub mod python;

use std::sync::OnceLock;

use tree_sitter::{Language, Node, Parser};

use crate::engine::secrets::{
    Candidate, REDACTION_PLACEHOLDER, SecretsEngine, digest_of, line_text, locate,
};
use crate::finding::{Diagnostic, Severity};
use lang::RulesLanguage;

/// A byte range identifying one matched construct; the engine derives the
/// location, redacted snippet and digest from it.
struct Hit {
    start: usize,
    end: usize,
}

/// Matcher over a parsed file: the source bytes plus the tree root.
/// Matchers only read node text; redaction and digesting stay centralized.
type Matcher = fn(source: &[u8], root: tree_sitter::Node<'_>) -> Vec<Hit>;

/// Static rule definition; adding a rule is a table entry plus its matcher.
#[derive(Clone, Copy)]
pub(crate) struct RuleDef {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    languages: &'static [RulesLanguage],
    matches: Matcher,
}

/// The production table; PR3 extends this list without other changes.
const RULE_DEFS: &[RuleDef] = &[
    javascript::WEAK_HASH_DEF,
    javascript::DYNAMIC_CODE_DEF,
    javascript::SHELL_INJECTION_DEF,
    python::WEAK_HASH_PY_DEF,
    python::SHELL_INJECTION_PY_DEF,
    python::UNSAFE_DESERIALIZATION_PY_DEF,
];

/// The code-rules engine over a compiled rule table.
pub struct RulesEngine {
    rules: Vec<RuleDef>,
    redactor: SecretsEngine,
    init_diagnostics: Vec<Diagnostic>,
}

impl RulesEngine {
    /// The engine over the pinned production table.
    pub fn new() -> Self {
        Self::from_defs(RULE_DEFS)
    }

    /// Builds an engine from explicit definitions; a definition that names
    /// no language can never apply, so it becomes a `rule-failed`
    /// diagnostic and is skipped — the remaining rules still fire
    /// (failure containment).
    pub fn from_defs(defs: &[RuleDef]) -> Self {
        let mut rules = Vec::new();
        let mut init_diagnostics = Vec::new();
        for def in defs {
            if def.languages.is_empty() {
                init_diagnostics.push(Diagnostic::rule_failed(
                    def.id,
                    "rule declares no applicable language".to_string(),
                ));
                continue;
            }
            rules.push(*def);
        }
        Self {
            rules,
            redactor: SecretsEngine::new(),
            init_diagnostics,
        }
    }

    /// Rule failures found at construction, warned once per scan.
    pub fn init_diagnostics(&self) -> &[Diagnostic] {
        &self.init_diagnostics
    }

    /// Scans one file; unsupported extensions and languages without rules
    /// return no candidates without any parse attempt. Candidates carry
    /// only redacted text and the pre-redaction digest. This is a thin
    /// wrapper: parse-failure diagnostics are discarded, use
    /// [`RulesEngine::scan_with_diagnostics`] when they matter.
    #[cfg(test)]
    pub fn scan(&self, path: &str, bytes: &[u8]) -> Vec<Candidate> {
        self.scan_with_diagnostics(path, bytes).0
    }

    /// Scans one file with its diagnostics. A file the grammar cannot
    /// fully parse is scanned by the same rules and matchers a parseable
    /// file uses, restricted to the regions the parser recovered: a match
    /// that sits inside a region the parser reported as damaged is
    /// discarded, and exactly one `rule-fallback` diagnostic discloses the
    /// reduced coverage. A file with no usable tree produces the diagnostic
    /// alone.
    pub fn scan_with_diagnostics(
        &self,
        path: &str,
        bytes: &[u8],
    ) -> (Vec<Candidate>, Vec<Diagnostic>) {
        let Some(language) = lang::detect(path) else {
            return (Vec::new(), Vec::new());
        };
        if !self
            .rules
            .iter()
            .any(|rule| rule.languages.contains(&language))
        {
            return (Vec::new(), Vec::new());
        }
        let mut parser = Parser::new();
        if parser.set_language(grammar(language)).is_err() {
            // Grammars are compiled in and validated at construction;
            // stay silent rather than invent a finding.
            return (Vec::new(), Vec::new());
        }
        let Some(tree) = parser.parse(bytes, None) else {
            return (
                Vec::new(),
                vec![Diagnostic::rule_fallback(
                    path,
                    "the file did not parse; no rule was applied",
                )],
            );
        };
        let root = tree.root_node();
        let degraded = root.has_error();
        let mut candidates = Vec::new();
        for rule in &self.rules {
            if !rule.languages.contains(&language) {
                continue;
            }
            for hit in (rule.matches)(bytes, root) {
                if degraded && in_damaged_region(root, hit.start, hit.end) {
                    continue;
                }
                candidates.push(self.candidate(rule.id, rule.severity, rule.message, bytes, hit));
            }
        }
        let diagnostics = if degraded {
            vec![Diagnostic::rule_fallback(
                path,
                "the file did not fully parse; only recovered regions were scanned",
            )]
        } else {
            Vec::new()
        };
        (candidates, diagnostics)
    }

    /// Builds one candidate through the shared boundary: the matched
    /// line redacted with the secrets table, the digest over the
    /// pre-redaction bytes.
    fn candidate(
        &self,
        id: &'static str,
        severity: Severity,
        message: &'static str,
        bytes: &[u8],
        hit: Hit,
    ) -> Candidate {
        let (line, column) = locate(bytes, hit.start);
        Candidate {
            rule_id: id.to_string(),
            severity,
            message: message.to_string(),
            line,
            column,
            snippet: self.redactor.redact(&line_text(bytes, hit.start)),
            evidence: REDACTION_PLACEHOLDER.to_string(),
            digest: digest_of(&bytes[hit.start..hit.end]),
        }
    }
}

/// True when a matched range sits in a region the parser reported as damaged.
/// The root of a degraded file always reports an error, so an ancestor's
/// blanket `has_error` can never be consulted here: only the matched node's own
/// subtree and its ancestors' error and missing markers are inspected.
fn in_damaged_region(root: Node<'_>, start: usize, end: usize) -> bool {
    let Some(node) = root.descendant_for_byte_range(start, end) else {
        // A range the tree cannot locate is not evidence, so it is discarded.
        return true;
    };
    if node.has_error() {
        return true;
    }
    let mut current = node.parent();
    while let Some(parent) = current {
        if parent.is_error() || parent.is_missing() {
            return true;
        }
        current = parent.parent();
    }
    false
}

/// Lazily compiled grammar holders (design D2): converted once per
/// language via `Language::from`, then shared across parallel file scans.
fn grammar(language: RulesLanguage) -> &'static Language {
    static JAVASCRIPT: OnceLock<Language> = OnceLock::new();
    static TYPESCRIPT: OnceLock<Language> = OnceLock::new();
    static TSX: OnceLock<Language> = OnceLock::new();
    static PYTHON: OnceLock<Language> = OnceLock::new();
    match language {
        RulesLanguage::JavaScript => {
            JAVASCRIPT.get_or_init(|| tree_sitter_javascript::LANGUAGE.into())
        }
        RulesLanguage::TypeScript => {
            TYPESCRIPT.get_or_init(|| tree_sitter_typescript::LANGUAGE_TYPESCRIPT.into())
        }
        RulesLanguage::Tsx => TSX.get_or_init(|| tree_sitter_typescript::LANGUAGE_TSX.into()),
        RulesLanguage::Python => PYTHON.get_or_init(|| tree_sitter_python::LANGUAGE.into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::secrets::REDACTION_PLACEHOLDER;
    use crate::finding::Severity;

    fn no_hits(_source: &[u8], _root: tree_sitter::Node) -> Vec<Hit> {
        Vec::new()
    }

    fn whole_input(source: &[u8], _root: tree_sitter::Node) -> Vec<Hit> {
        vec![Hit {
            start: 0,
            end: source.len(),
        }]
    }

    // Synthetic rule with no real-world meaning; it exists only to exercise
    // the candidate boundary (location, redaction, digest) without depending
    // on any pinned rule.
    const SYNTHETIC_DEF: RuleDef = RuleDef {
        id: "RULE-synthetic",
        severity: Severity::Medium,
        message: "synthetic rule for boundary tests",
        languages: &[RulesLanguage::JavaScript],
        matches: whole_input,
    };

    #[test]
    fn unsupported_files_are_skipped_silently() {
        let engine = RulesEngine::new();
        let bytes = b"crypto.createHash('md5');";
        for path in ["main.rs", "README.md", "Makefile", "script"] {
            assert!(engine.scan(path, bytes).is_empty(), "path {path}");
        }
    }

    #[test]
    fn failing_rule_is_contained_and_named() {
        let broken = RuleDef {
            id: "RULE-broken",
            severity: Severity::High,
            message: "broken rule",
            languages: &[],
            matches: no_hits,
        };
        let engine = RulesEngine::from_defs(&[broken, SYNTHETIC_DEF]);
        let diagnostics = engine.init_diagnostics();
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-failed");
        assert_eq!(diagnostics[0].rule, "RULE-broken");
        let found = engine.scan("a.js", b"const h = 1;");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-synthetic");
    }

    #[test]
    fn degraded_files_never_report_what_the_parseable_twin_would_not() {
        let engine = RulesEngine::new();
        let cases = [
            ("a.js", "other.createHash('md5');\nfunction broken( {\n"),
            ("a.js", "crypto.CREATEHASH('md5');\nfunction broken( {\n"),
            ("a.js", "// crypto.createHash('md5');\nfunction broken( {\n"),
            (
                "a.js",
                "const s = \"crypto.createHash('md5')\";\nfunction broken( {\n",
            ),
            ("a.js", "obj.eval(userInput);\nfunction broken( {\n"),
            (
                "a.js",
                "child_process.exec(cmd, {x: a + b});\nfunction broken( {\n",
            ),
            (
                "a.js",
                "child_process.exec(cmd /* + x */);\nfunction broken( {\n",
            ),
            (
                "a.js",
                "eval(\"print(1)\");\ncrypto.createHash(\"sha256\");\nfunction broken( {\n",
            ),
            ("a.py", "foo.hashlib.md5(data)\ndef broken( :\n"),
            (
                "a.py",
                "subprocess.run(cmd, shell=Trueish)\ndef broken( :\n",
            ),
            (
                "a.py",
                "x = \"subprocess.run(cmd, shell=True)\"\ndef broken( :\n",
            ),
            (
                "a.py",
                "yaml.load(\n    data,\n    Loader=yaml.SafeLoader)\ndef broken( :\n",
            ),
        ];
        let mut invented = Vec::new();
        for (path, source) in cases {
            let (found, diagnostics) = engine.scan_with_diagnostics(path, source.as_bytes());
            if !found.is_empty() {
                invented.push((path, source, found));
            }
            assert_eq!(
                diagnostics.len(),
                1,
                "path {path} source {source:?}: expected exactly one diagnostic"
            );
            assert_eq!(diagnostics[0].code, "rule-fallback");
        }
        assert!(
            invented.is_empty(),
            "degraded scan invented findings: {invented:?}"
        );
    }

    #[test]
    fn degraded_javascript_still_reports_recovered_regions_and_warns_once() {
        let (found, diagnostics) = RulesEngine::new().scan_with_diagnostics(
            "broken.js",
            b"const h = crypto.createHash('md5');\nfunction broken( {\n",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-fallback");
        assert_eq!(diagnostics[0].path, "broken.js");
    }

    #[test]
    fn parseable_files_emit_no_fallback_diagnostic() {
        let (found, diagnostics) = RulesEngine::new()
            .scan_with_diagnostics("a.js", b"const h = crypto.createHash('md5');\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert!(diagnostics.is_empty(), "got {diagnostics:?}");
    }

    #[test]
    fn degraded_file_without_a_match_warns_once_and_reports_nothing() {
        let (found, diagnostics) =
            RulesEngine::new().scan_with_diagnostics("a.js", b"const h = 1;\nfunction broken( {\n");
        assert!(found.is_empty(), "got {found:?}");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-fallback");
    }

    #[test]
    fn degraded_and_parseable_scans_agree_on_location_and_digest() {
        let engine = RulesEngine::new();
        let (clean_found, clean_diagnostics) =
            engine.scan_with_diagnostics("a.js", b"crypto.createHash('md5');\n");
        let (recovered_found, recovered_diagnostics) = engine
            .scan_with_diagnostics("a.js", b"crypto.createHash('md5');\nfunction broken( {\n");
        assert_eq!(clean_found.len(), 1);
        assert_eq!(recovered_found.len(), 1);
        assert_eq!(
            (recovered_found[0].line, recovered_found[0].column),
            (clean_found[0].line, clean_found[0].column),
        );
        assert_eq!(recovered_found[0].digest, clean_found[0].digest);
        assert!(clean_diagnostics.is_empty(), "got {clean_diagnostics:?}");
        assert_eq!(recovered_diagnostics.len(), 1);
        assert_eq!(recovered_diagnostics[0].code, "rule-fallback");
    }

    #[test]
    fn secret_inside_a_matched_line_is_redacted() {
        let found = RulesEngine::from_defs(&[SYNTHETIC_DEF]).scan(
            "a.js",
            b"const h = crypto.createHash('md5'); // sk-synthetic-1234567890",
        );
        assert_eq!(found.len(), 1);
        assert!(
            !found[0].snippet.contains("sk-synthetic-1234567890"),
            "raw value leaked via {:?}",
            found[0].snippet
        );
        assert!(found[0].snippet.contains(REDACTION_PLACEHOLDER));
        assert_eq!(found[0].evidence, REDACTION_PLACEHOLDER);
    }
}
