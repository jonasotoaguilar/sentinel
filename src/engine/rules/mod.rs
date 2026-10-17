//! Code-rules engine over the pinned rule table below (JavaScript, TypeScript,
//! TSX, Python); adding a rule is a table entry plus its matcher.

pub mod javascript;
pub mod lang;
pub mod python;

use std::cell::{Cell, RefCell};
use std::sync::OnceLock;
use std::sync::atomic::{AtomicUsize, Ordering};

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

/// Parsers constructed process-wide. Mirrors the OSV client's `CONSTRUCTIONS`
/// counter: a production-visible count, not a test-only one, incremented
/// exactly where a `Parser` is built.
static PARSER_CONSTRUCTIONS: AtomicUsize = AtomicUsize::new(0);

/// One thread's reused parser plus the language it is currently set to.
/// `set_language` deletes and re-copies the whole grammar table, so it
/// runs only when the language actually changes between files on the
/// same thread.
struct ThreadParser {
    parser: Parser,
    language: Option<RulesLanguage>,
}

thread_local! {
    // One `Parser` per thread: the scan is a rayon `par_iter`, so each
    // worker thread parses many files over its lifetime and builds at most
    // one parser for the whole scan. A `Parser` carries mutable parse state
    // and cannot be shared, but threads never share work here either, so no
    // pool and no `Mutex` is needed. The grammars stay in their `OnceLock`s;
    // only the parser itself is per-thread.
    static THREAD_PARSER: RefCell<Option<ThreadParser>> = const { RefCell::new(None) };
    // Parsers constructed on the calling thread. A fresh thread starts at
    // zero, so a reuse probe on a spawned thread is deterministic no matter
    // what other tests build on other threads in parallel.
    static THREAD_PARSER_CONSTRUCTIONS: Cell<usize> = const { Cell::new(0) };
}

/// Number of `Parser`s constructed so far across all threads.
pub fn parser_constructions() -> usize {
    PARSER_CONSTRUCTIONS.load(Ordering::SeqCst)
}

/// Number of `Parser`s constructed so far on the calling thread.
pub fn thread_parser_constructions() -> usize {
    THREAD_PARSER_CONSTRUCTIONS.with(|count| count.get())
}

/// Records one `Parser` construction in both counters.
fn note_parser_construction() {
    PARSER_CONSTRUCTIONS.fetch_add(1, Ordering::SeqCst);
    THREAD_PARSER_CONSTRUCTIONS.with(|count| count.set(count.get() + 1));
}

/// Runs `f` on this thread's reused parser, constructing it on first use.
/// The grammar is installed only when it differs from the parser's current
/// one: one thread parses files of many languages over its lifetime, and
/// reinstalling the same grammar would delete and re-copy its tables for
/// every file. A `None` return means the grammar itself could not be
/// installed (compiled-in grammars: unreachable in practice); the caller
/// stays silent, exactly like a per-file parser that rejects its language.
fn with_thread_parser<R>(language: RulesLanguage, f: impl FnOnce(&mut Parser) -> R) -> Option<R> {
    THREAD_PARSER.with(|slot| {
        let mut slot = slot.borrow_mut();
        let entry = slot.get_or_insert_with(|| {
            note_parser_construction();
            ThreadParser {
                parser: Parser::new(),
                language: None,
            }
        });
        if entry.language != Some(language) {
            if entry.parser.set_language(grammar(language)).is_err() {
                return None;
            }
            entry.language = Some(language);
        }
        // The counters' contract, checked where the parser is handed out:
        // this thread owns a constructed parser, and the process-wide
        // count covers every thread's constructions.
        debug_assert!(thread_parser_constructions() >= 1);
        debug_assert!(parser_constructions() >= thread_parser_constructions());
        Some(f(&mut entry.parser))
    })
}

/// Static rule definition; adding a rule is a table entry plus its matcher.
#[derive(Clone, Copy)]
pub(crate) struct RuleDef {
    id: &'static str,
    severity: Severity,
    message: &'static str,
    languages: &'static [RulesLanguage],
    matches: Matcher,
}

/// The production table; extending it is a table entry plus its matcher.
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
    /// fully parse is skipped and said so: no finding is reported for it
    /// and exactly one `rule-fallback` diagnostic names the path. The
    /// engine declines to guess what the text was meant to be, because
    /// every recovery from a parse failure is a guess about intent and
    /// two such guesses have been shown to invent findings.
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
        let Some(tree) = with_thread_parser(language, |parser| parser.parse(bytes, None)) else {
            // Grammars are compiled in and validated at construction;
            // stay silent rather than invent a finding.
            return (Vec::new(), Vec::new());
        };
        let Some(tree) = tree else {
            return (
                Vec::new(),
                vec![Diagnostic::rule_fallback(
                    path,
                    "the file did not fully parse; no rule was applied to it",
                )],
            );
        };
        let root = tree.root_node();
        if root.has_error() {
            return (
                Vec::new(),
                vec![Diagnostic::rule_fallback(
                    path,
                    "the file did not fully parse; no rule was applied to it",
                )],
            );
        }
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
    fn one_thread_reuses_a_single_parser() {
        // A spawned thread starts with no parser, so its per-thread count
        // is zero regardless of what other tests build on other threads.
        // Two parses on that thread must construct exactly one parser.
        std::thread::spawn(|| {
            let engine = RulesEngine::new();
            let _ = engine.scan_with_diagnostics("a.js", b"const h = 1;\n");
            let _ = engine.scan_with_diagnostics("a.js", b"const h = 2;\n");
            assert_eq!(
                thread_parser_constructions(),
                1,
                "two parses on one thread constructed {} parsers, expected 1",
                thread_parser_constructions()
            );
        })
        .join()
        .expect("parser reuse probe thread panicked");
    }

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
    fn degraded_recovery_does_not_promote_the_next_line_of_a_broken_delimiter() {
        let engine = RulesEngine::new();
        let cases = [
            (
                "a.py",
                "s = \"subprocess.run(cmd, shell=True)\n",
                "s = \"subprocess.run(cmd, shell=True)\"\n",
            ),
            (
                "a.py",
                "s = \"hashlib.md5(data)\n",
                "s = \"hashlib.md5(data)\"\n",
            ),
            (
                "a.py",
                "s = \"pickle.loads(payload)\n",
                "s = \"pickle.loads(payload)\"\n",
            ),
            (
                "a.py",
                "s = \"yaml.load(data)\n",
                "s = \"yaml.load(data)\"\n",
            ),
            (
                "a.js",
                "const s = \"hello\ncrypto.createHash('md5');\n",
                "const s = \"hello crypto.createHash('md5');\";\n",
            ),
            (
                "a.ts",
                "const s = \"\neval(userInput);\n",
                "const s = \"eval(userInput);\";\n",
            ),
            (
                "a.tsx",
                "const s = \"\nchild_process.exec(`ls ${dir}`);\n",
                "const s = \"child_process.exec(`ls ${dir}`);\";\n",
            ),
            (
                "a.js",
                "/* hello\ncrypto.createHash('md5');\n",
                "/* hello\ncrypto.createHash('md5');\n*/\n",
            ),
        ];
        for (path, degraded, twin) in cases {
            let (found, diagnostics) = engine.scan_with_diagnostics(path, degraded.as_bytes());
            let (twin_found, twin_diagnostics) =
                engine.scan_with_diagnostics(path, twin.as_bytes());
            assert!(
                twin_diagnostics.is_empty() && twin_found.is_empty(),
                "{path} {twin:?}"
            );
            assert!(
                found.is_empty(),
                "{path} invented {found:?} from {degraded:?}"
            );
            assert_eq!(diagnostics.len(), 1);
            assert_eq!(diagnostics[0].code, "rule-fallback");
            assert_eq!(diagnostics[0].path, path);
        }
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
