//! JavaScript/TypeScript rules for the code-rules engine.

use super::lang::RulesLanguage;
use super::{Hit, RuleDef};
use crate::finding::Severity;

pub(crate) const WEAK_HASH_DEF: RuleDef = RuleDef {
    id: "RULE-weak-hash",
    severity: Severity::Medium,
    message: "weak cryptographic hash (md5 or sha1) detected",
    languages: &[
        RulesLanguage::JavaScript,
        RulesLanguage::TypeScript,
        RulesLanguage::Tsx,
    ],
    matches: match_weak_hash,
};

pub(crate) const DYNAMIC_CODE_DEF: RuleDef = RuleDef {
    id: "RULE-dynamic-code",
    severity: Severity::Critical,
    message: "dynamic code execution with a non-literal argument detected",
    languages: &[
        RulesLanguage::JavaScript,
        RulesLanguage::TypeScript,
        RulesLanguage::Tsx,
    ],
    matches: match_dynamic_code,
};

pub(crate) const SHELL_INJECTION_DEF: RuleDef = RuleDef {
    id: "RULE-shell-injection",
    severity: Severity::Critical,
    message: "shell command built from interpolated or concatenated input detected",
    languages: &[
        RulesLanguage::JavaScript,
        RulesLanguage::TypeScript,
        RulesLanguage::Tsx,
    ],
    matches: match_shell_injection,
};

/// `eval(<non-literal>)` and `new Function(<non-literal body>)`. The body
/// decision looks only at the last argument, so `new Function("a", body)`
/// reports while `new Function("a", "return 1")` stays clean.
fn match_dynamic_code(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_node(root, |node| {
        let is_hit = match node.kind() {
            "call_expression" => is_non_literal_eval(source, node),
            "new_expression" => is_non_literal_function(source, node),
            _ => false,
        };
        if is_hit {
            hits.push(Hit {
                start: node.start_byte(),
                end: node.end_byte(),
            });
        }
    });
    hits
}

/// `exec`/`execSync` whose command argument is an interpolated template
/// string or a `+` concatenation. A bare identifier stays clean because
/// without dataflow it cannot be told apart from a constant.
fn match_shell_injection(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_node(root, |node| {
        if node.kind() == "call_expression" && is_dangerous_exec(source, node) {
            hits.push(Hit {
                start: node.start_byte(),
                end: node.end_byte(),
            });
        }
    });
    hits
}

/// A bare `eval(...)` call whose first argument is not a compile-time
/// literal; a missing first argument is not a finding.
fn is_non_literal_eval(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "identifier" || text_of(source, function) != Some("eval") {
        return false;
    }
    let Some(first) = first_argument(call) else {
        return false;
    };
    literal_string(source, first).is_none()
}

/// `new Function(...)` whose last (body) argument is not a compile-time
/// literal; no arguments, or all-literal arguments, is not a finding.
fn is_non_literal_function(source: &[u8], node: tree_sitter::Node) -> bool {
    let Some(constructor) = node.child_by_field_name("constructor") else {
        return false;
    };
    if constructor.kind() != "identifier" || text_of(source, constructor) != Some("Function") {
        return false;
    }
    let Some(arguments) = node.child_by_field_name("arguments") else {
        return false;
    };
    if arguments.kind() != "arguments" {
        return false;
    }
    let count = arguments.named_child_count();
    if count == 0 {
        return false;
    }
    let Ok(last_index) = u32::try_from(count - 1) else {
        return false;
    };
    let Some(last) = arguments.named_child(last_index) else {
        return false;
    };
    literal_string(source, last).is_none()
}

/// An `exec`/`execSync` call, either bare or through a member expression,
/// whose command argument is interpolated or concatenated.
fn is_dangerous_exec(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    let is_exec = match function.kind() {
        "identifier" => matches!(text_of(source, function), Some("exec" | "execSync")),
        "member_expression" => {
            let Some(property) = function.child_by_field_name("property") else {
                return false;
            };
            matches!(text_of(source, property), Some("exec" | "execSync"))
        }
        _ => false,
    };
    if !is_exec {
        return false;
    }
    let Some(first) = first_argument(call) else {
        return false;
    };
    match first.kind() {
        "template_string" => interpolates(first),
        "binary_expression" => uses_plus(source, first),
        _ => false,
    }
}

/// The first call argument; a tagged template passes its `template_string`
/// directly as the arguments field, so it counts as the command itself.
fn first_argument(call: tree_sitter::Node) -> Option<tree_sitter::Node> {
    let arguments = call.child_by_field_name("arguments")?;
    if arguments.kind() == "template_string" {
        return Some(arguments);
    }
    if arguments.kind() != "arguments" {
        return None;
    }
    arguments.named_child(0)
}

/// Whether a `binary_expression` concatenates with `+`.
fn uses_plus(source: &[u8], node: tree_sitter::Node) -> bool {
    let Some(operator) = node.child_by_field_name("operator") else {
        return false;
    };
    text_of(source, operator) == Some("+")
}
/// `crypto.createHash(<literal 'md5' or 'sha1'>)`; matching is name-based
/// with no import resolution, so any receiver other than `crypto`, or any
/// non-literal first argument, is ignored.
fn match_weak_hash(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_call(root, |call| {
        if is_weak_hash_call(source, call) {
            hits.push(Hit {
                start: call.start_byte(),
                end: call.end_byte(),
            });
        }
    });
    hits
}

fn is_weak_hash_call(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "member_expression" {
        return false;
    }
    let (Some(object), Some(property)) = (
        function.child_by_field_name("object"),
        function.child_by_field_name("property"),
    ) else {
        return false;
    };
    if object.kind() != "identifier" || text_of(source, object) != Some("crypto") {
        return false;
    }
    if property.kind() != "property_identifier" || text_of(source, property) != Some("createHash") {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    if arguments.kind() != "arguments" {
        return false;
    }
    let Some(first) = arguments.named_child(0) else {
        return false;
    };
    let Some(algorithm) = literal_string(source, first) else {
        return false;
    };
    matches!(algorithm.to_ascii_lowercase().as_str(), "md5" | "sha1")
}

/// Visits every `call_expression` in document order with an explicit stack
/// rather than recursion, so hostile nesting cannot overflow the stack.
fn each_call(root: tree_sitter::Node, mut visit: impl FnMut(tree_sitter::Node)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call_expression" {
            visit(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

/// Visits every syntax node in document order; the dynamic-code rule needs
/// both `call_expression` and `new_expression` from one walk.
fn each_node(root: tree_sitter::Node, mut visit: impl FnMut(tree_sitter::Node)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        visit(node);
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

fn text_of<'a>(source: &'a [u8], node: tree_sitter::Node) -> Option<&'a str> {
    node.utf8_text(source).ok()
}

/// Strips one pair of surrounding quotes (single, double, or backtick);
/// anything else is returned unchanged.
fn strip_quotes(text: &str) -> &str {
    let bytes = text.as_bytes();
    if bytes.len() >= 2 {
        let (first, last) = (bytes[0], bytes[bytes.len() - 1]);
        if first == last && matches!(first, b'\'' | b'"' | b'`') {
            return &text[1..text.len() - 1];
        }
    }
    text
}

/// The compile-time literal text of an argument: a `string` node, or a
/// `template_string` with no interpolation. This literal/non-literal split is
/// what the rule set exists to express, and the dynamic-code rule reuses it.
fn literal_string<'a>(source: &'a [u8], node: tree_sitter::Node) -> Option<&'a str> {
    match node.kind() {
        "string" => text_of(source, node).map(strip_quotes),
        "template_string" if !interpolates(node) => text_of(source, node).map(strip_quotes),
        _ => None,
    }
}

/// Whether a `template_string` interpolates anything (`${...}`).
fn interpolates(node: tree_sitter::Node) -> bool {
    let mut cursor = node.walk();
    node.named_children(&mut cursor)
        .any(|child| child.kind() == "template_substitution")
}

#[cfg(test)]
mod tests {
    use crate::engine::rules::RulesEngine;
    use crate::finding::Severity;

    #[test]
    fn weak_hash_fires_with_pinned_id_and_severity() {
        let engine = RulesEngine::new();
        assert!(engine.init_diagnostics().is_empty());
        let found = engine.scan("a.js", b"const h = crypto.createHash('md5');");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_fires_for_sha1_and_double_quotes() {
        let found = RulesEngine::new().scan("b.ts", b"crypto.createHash(\"sha1\")");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_ignores_sha256_and_other_receivers() {
        let engine = RulesEngine::new();
        assert!(
            engine
                .scan("a.js", b"crypto.createHash('sha256');")
                .is_empty()
        );
        assert!(engine.scan("a.js", b"other.createHash('md5');").is_empty());
    }

    #[test]
    fn weak_hash_fires_for_a_substitution_free_template_literal() {
        let found = RulesEngine::new().scan("a.js", b"crypto.createHash(`md5`);");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash");
    }

    #[test]
    fn weak_hash_algorithm_name_is_case_insensitive() {
        let engine = RulesEngine::new();
        assert_eq!(engine.scan("a.js", b"crypto.createHash('MD5');").len(), 1);
        assert_eq!(
            engine.scan("a.js", b"crypto.createHash(\"Sha1\");").len(),
            1
        );
    }

    #[test]
    fn weak_hash_ignores_a_template_literal_with_interpolation() {
        let found = RulesEngine::new().scan("a.js", b"crypto.createHash(`md${5}`);");
        assert!(found.is_empty(), "got {found:?}");
    }

    #[test]
    fn dynamic_code_fires_for_non_literal_eval() {
        let engine = RulesEngine::new();
        for source in [
            b"eval(userInput)".as_slice(),
            b"eval(a + b)".as_slice(),
            b"eval(`x${y}`)".as_slice(),
        ] {
            let found = engine.scan("a.js", source);
            assert_eq!(found.len(), 1, "source {source:?}");
            assert_eq!(found[0].rule_id, "RULE-dynamic-code");
            assert_eq!(found[0].severity, Severity::Critical);
        }
    }

    #[test]
    fn dynamic_code_fires_for_non_literal_function_body() {
        let found = RulesEngine::new().scan("a.js", b"new Function(body)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-dynamic-code");
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn dynamic_code_ignores_literal_arguments() {
        let engine = RulesEngine::new();
        for source in [
            b"eval(\"print(1)\")".as_slice(),
            b"eval(`print(1)`)".as_slice(),
            b"new Function(\"return 1\")".as_slice(),
            b"new Function()".as_slice(),
        ] {
            assert!(engine.scan("a.js", source).is_empty(), "source {source:?}");
        }
    }

    #[test]
    fn shell_injection_fires_for_interpolated_or_concatenated_command() {
        let engine = RulesEngine::new();
        let found = engine.scan("a.js", b"child_process.exec(`ls ${dir}`)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-shell-injection");
        assert_eq!(found[0].severity, Severity::Critical);
        let found = engine.scan(
            "a.js",
            b"require(\"child_process\").execSync(\"ls \" + dir)",
        );
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-shell-injection");
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn shell_injection_ignores_literal_and_bare_identifier() {
        let engine = RulesEngine::new();
        assert!(
            engine
                .scan("a.js", b"child_process.exec(\"ls -la\")")
                .is_empty()
        );
        assert!(engine.scan("a.js", b"child_process.exec(cmd)").is_empty());
    }

    #[test]
    fn new_rules_apply_to_typescript_variants() {
        let engine = RulesEngine::new();
        let found = engine.scan("a.ts", b"eval(userInput)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-dynamic-code");
        assert_eq!(found[0].severity, Severity::Critical);
        let found = engine.scan("b.tsx", b"child_process.exec(`ls ${dir}`)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-shell-injection");
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn new_rules_do_not_apply_to_python() {
        let found = RulesEngine::new().scan("python.py", b"import subprocess");
        assert!(
            found
                .iter()
                .all(|candidate| candidate.rule_id != "RULE-dynamic-code"
                    && candidate.rule_id != "RULE-shell-injection"),
            "got {found:?}"
        );
    }
}
