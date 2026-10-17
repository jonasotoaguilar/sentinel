//! Conservative regex fallback for files the grammar cannot parse
//! (code-rules spec: parse-failure degradation; design D6). Each entry
//! mirrors one AST rule textually and borrows the AST definition itself,
//! so identity, severity and language gating cannot drift between the two
//! paths. Where the textual form cannot decide, the entry stays silent
//! rather than over-report.

use regex::bytes::Regex;

use super::RuleDef;
use super::javascript::{DYNAMIC_CODE_DEF, SHELL_INJECTION_DEF, WEAK_HASH_DEF};
use super::python::{SHELL_INJECTION_PY_DEF, UNSAFE_DESERIALIZATION_PY_DEF, WEAK_HASH_PY_DEF};
use crate::engine::secrets::line_text;
use crate::finding::Diagnostic;

/// One conservative textual mirror of an AST rule; `rule` is the AST
/// definition, so a finding keeps its identity whichever path found it.
#[derive(Clone, Copy)]
pub(crate) struct FallbackDef {
    pub rule: &'static RuleDef,
    pub pattern: &'static str,
    pub rejection: Option<&'static str>,
}

/// The pinned fallback table: a separate rejection pattern stands in for
/// the lookaround the `regex` crate cannot express — a match whose line
/// also matches it is dropped.
pub(crate) const FALLBACK_DEFS: &[FallbackDef] = &[
    FallbackDef {
        rule: &WEAK_HASH_DEF,
        pattern: r#"(?i)\bcreateHash\s*\(\s*["'`](?:md5|sha1)["'`]\s*\)"#,
        rejection: None,
    },
    FallbackDef {
        rule: &DYNAMIC_CODE_DEF,
        pattern: r#"\beval\s*\(\s*[^"'`\s)]"#,
        rejection: None,
    },
    FallbackDef {
        rule: &DYNAMIC_CODE_DEF,
        pattern: r#"\bnew\s+Function\s*\(\s*[^"'`\s)]"#,
        rejection: None,
    },
    FallbackDef {
        rule: &SHELL_INJECTION_DEF,
        pattern: r"\bexec(?:Sync)?\s*\([^)]*(?:\$\{|\+\s*[A-Za-z_$])",
        rejection: None,
    },
    FallbackDef {
        rule: &WEAK_HASH_PY_DEF,
        pattern: r"\bhashlib\.(?:md5|sha1)\s*\(",
        rejection: None,
    },
    FallbackDef {
        rule: &SHELL_INJECTION_PY_DEF,
        pattern: r"\bsubprocess\.[A-Za-z_]+\s*\([^)]*shell\s*=\s*True",
        rejection: None,
    },
    FallbackDef {
        rule: &UNSAFE_DESERIALIZATION_PY_DEF,
        pattern: r"\b(?:pickle\.loads?|yaml\.load)\s*\(",
        rejection: Some(r"Loader\s*="),
    },
];

/// A fallback entry with its patterns compiled.
pub(crate) struct CompiledFallback {
    pub rule: RuleDef,
    pub regex: Regex,
    pub rejection: Option<Regex>,
}

/// Compiles a fallback table; an entry whose pattern cannot compile
/// becomes one `rule-failed` diagnostic and is skipped, exactly like the
/// AST rules — the remaining entries still run.
pub(crate) fn compile_fallback(defs: &[FallbackDef]) -> (Vec<CompiledFallback>, Vec<Diagnostic>) {
    let mut compiled = Vec::new();
    let mut diagnostics = Vec::new();
    for def in defs {
        match compile_one(def) {
            Ok(entry) => compiled.push(entry),
            Err(diagnostic) => diagnostics.push(diagnostic),
        }
    }
    (compiled, diagnostics)
}

fn compile_one(def: &FallbackDef) -> Result<CompiledFallback, Diagnostic> {
    let regex = Regex::new(def.pattern)
        .map_err(|error| Diagnostic::rule_failed(def.rule.id, error.to_string()))?;
    let rejection = def
        .rejection
        .map(|pattern| {
            Regex::new(pattern)
                .map_err(|error| Diagnostic::rule_failed(def.rule.id, error.to_string()))
        })
        .transpose()?;
    Ok(CompiledFallback {
        rule: *def.rule,
        regex,
        rejection,
    })
}

impl CompiledFallback {
    /// Byte ranges of every non-rejected occurrence; each match produces
    /// its own candidate downstream. The rejection runs over the match's
    /// line, decoded lossily like every other snippet read.
    pub fn find_ranges(&self, bytes: &[u8]) -> Vec<(usize, usize)> {
        let mut ranges = Vec::new();
        for matched in self.regex.find_iter(bytes) {
            if let Some(rejection) = &self.rejection
                && rejection.is_match(line_text(bytes, matched.start()).as_bytes())
            {
                continue;
            }
            ranges.push((matched.start(), matched.end()));
        }
        ranges
    }
}

#[cfg(test)]
mod tests {
    use super::{FALLBACK_DEFS, FallbackDef, compile_fallback};
    use crate::engine::rules::RulesEngine;
    use crate::engine::rules::javascript::WEAK_HASH_DEF;

    const BROKEN_JS: &[u8] = b"const h = crypto.createHash('md5');\nfunction broken( {\n";

    #[test]
    fn unparseable_javascript_still_reports_and_warns_once() {
        let (found, diagnostics) = RulesEngine::new().scan_with_diagnostics("broken.js", BROKEN_JS);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-fallback");
        assert_eq!(diagnostics[0].path, "broken.js");
    }

    #[test]
    fn fallback_stays_silent_for_literal_only_constructs() {
        let bytes = b"eval(\"print(1)\");\ncrypto.createHash(\"sha256\");\nfunction broken( {\n";
        let (found, diagnostics) = RulesEngine::new().scan_with_diagnostics("broken.js", bytes);
        assert!(found.is_empty(), "fallback invented {found:?}");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-fallback");
    }

    #[test]
    fn safe_loader_suppresses_yaml_load_while_bare_load_fires() {
        let engine = RulesEngine::new();
        let suppressed = b"yaml.load(data, Loader=yaml.SafeLoader)\ndef broken( :\n";
        let (found, _) = engine.scan_with_diagnostics("broken.py", suppressed);
        assert!(found.is_empty(), "rejection missed {found:?}");
        let bare = b"yaml.load(data)\ndef broken( :\n";
        let (found, diagnostics) = engine.scan_with_diagnostics("broken.py", bare);
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-unsafe-deserialization-python");
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-fallback");
    }

    #[test]
    fn fallback_does_not_fire_on_cleanly_parsed_files() {
        let (found, diagnostics) =
            RulesEngine::new().scan_with_diagnostics("a.js", b"const h = 1;\n");
        assert!(found.is_empty());
        assert!(diagnostics.is_empty());
        let (found, diagnostics) = RulesEngine::new()
            .scan_with_diagnostics("a.js", b"const h = crypto.createHash('md5');\n");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert!(diagnostics.is_empty(), "AST path owns clean files");
    }

    #[test]
    fn uncompilable_fallback_pattern_is_contained() {
        let broken = FallbackDef {
            rule: &WEAK_HASH_DEF,
            pattern: "[",
            rejection: None,
        };
        let defs = [broken, FALLBACK_DEFS[0]];
        let (compiled, diagnostics) = compile_fallback(&defs);
        assert_eq!(compiled.len(), 1);
        assert_eq!(diagnostics.len(), 1);
        assert_eq!(diagnostics[0].code, "rule-failed");
        assert_eq!(diagnostics[0].rule, "RULE-weak-hash");
    }
}
