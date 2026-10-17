//! Extension to grammar selection for the code-rules engine (code-rules
//! spec: language detection by extension). Extensions match
//! case-insensitively; `.tsx` selects the TSX grammar variant while every
//! other `ts`-family extension selects the TypeScript one.

/// Grammar family selected for a path; one variant per Tree-sitter grammar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RulesLanguage {
    JavaScript,
    TypeScript,
    Tsx,
    Python,
}

/// Selects the grammar for a path by its extension, case-insensitively.
/// Returns `None` for unlisted extensions and extensionless paths; those
/// files are skipped silently (no finding, no diagnostic, no parse attempt).
pub fn detect(path: &str) -> Option<RulesLanguage> {
    let file = path.rsplit(['/', '\\']).next().unwrap_or(path);
    let extension = file.rsplit('.').next()?;
    if extension.len() == file.len() {
        return None; // No `.` in the file name: no extension.
    }
    match extension.to_ascii_lowercase().as_str() {
        "js" | "mjs" | "cjs" | "jsx" => Some(RulesLanguage::JavaScript),
        "ts" | "mts" | "cts" => Some(RulesLanguage::TypeScript),
        "tsx" => Some(RulesLanguage::Tsx),
        "py" | "pyi" => Some(RulesLanguage::Python),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn all_listed_extensions_select_a_grammar() {
        let cases = [
            ("a.js", RulesLanguage::JavaScript),
            ("b.mjs", RulesLanguage::JavaScript),
            ("c.cjs", RulesLanguage::JavaScript),
            ("d.jsx", RulesLanguage::JavaScript),
            ("e.ts", RulesLanguage::TypeScript),
            ("f.mts", RulesLanguage::TypeScript),
            ("g.cts", RulesLanguage::TypeScript),
            ("h.tsx", RulesLanguage::Tsx),
            ("i.py", RulesLanguage::Python),
            ("j.pyi", RulesLanguage::Python),
        ];
        for (path, expected) in cases {
            assert_eq!(detect(path), Some(expected), "path {path}");
        }
    }

    #[test]
    fn tsx_selects_the_tsx_variant() {
        assert_eq!(detect("h.tsx"), Some(RulesLanguage::Tsx));
        assert_eq!(detect("e.ts"), Some(RulesLanguage::TypeScript));
    }

    #[test]
    fn unsupported_paths_are_skipped_silently() {
        for path in ["main.rs", "README.md", "Makefile", "script", "a.json"] {
            assert_eq!(detect(path), None, "path {path}");
        }
    }

    #[test]
    fn extension_matching_is_case_insensitive() {
        assert_eq!(detect("A.JS"), Some(RulesLanguage::JavaScript));
        assert_eq!(detect("B.TSX"), Some(RulesLanguage::Tsx));
        assert_eq!(detect("C.PY"), Some(RulesLanguage::Python));
    }
}
