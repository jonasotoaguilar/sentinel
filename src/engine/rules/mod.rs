//! Code-rules engine (PR1 skeleton plus the JavaScript/TypeScript rule set);
//! Python rules arrive as further entries in the rule table.

pub mod fallback;
pub mod javascript;
pub mod lang;
pub mod python;

use std::sync::OnceLock;

use tree_sitter::{Language, Parser};

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
    fallback: Vec<fallback::CompiledFallback>,
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
        // Fallback entries compile with the same containment: one
        // `rule-failed` diagnostic per bad pattern, the rest still run.
        let (fallback, fallback_diagnostics) = fallback::compile_fallback(fallback::FALLBACK_DEFS);
        init_diagnostics.extend(fallback_diagnostics);
        Self {
            rules,
            fallback,
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
    /// parse — no tree, or a tree whose root reports an error — degrades
    /// to the conservative fallback for that file only: no AST rule runs
    /// on the untrustworthy tree, and exactly one `rule-fallback`
    /// diagnostic names the path.
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
            return self.fallback_for(path, language, bytes);
        };
        if tree.root_node().has_error() {
            return self.fallback_for(path, language, bytes);
        }
        let root = tree.root_node();
        let mut candidates = Vec::new();
        for rule in &self.rules {
            if !rule.languages.contains(&language) {
                continue;
            }
            for hit in (rule.matches)(bytes, root) {
                candidates.push(self.candidate(rule.id, rule.severity, rule.message, bytes, hit));
            }
        }
        (candidates, Vec::new())
    }

    /// Conservative regex coverage for one unparseable file, gated by the
    /// file's language like the AST rules.
    fn fallback_for(
        &self,
        path: &str,
        language: lang::RulesLanguage,
        bytes: &[u8],
    ) -> (Vec<Candidate>, Vec<Diagnostic>) {
        let diagnostic =
            Diagnostic::rule_fallback(path, "parse failed; applied conservative fallback");
        let mut candidates = Vec::new();
        for rule in &self.fallback {
            if !rule.rule.languages.contains(&language) {
                continue;
            }
            for (start, end) in rule.find_ranges(bytes) {
                candidates.push(self.candidate(
                    rule.rule.id,
                    rule.rule.severity,
                    rule.rule.message,
                    bytes,
                    Hit { start, end },
                ));
            }
        }
        (candidates, vec![diagnostic])
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
