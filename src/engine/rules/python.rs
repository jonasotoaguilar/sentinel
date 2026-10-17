//! Python rules for the code-rules engine.

use super::lang::RulesLanguage;
use super::{Hit, RuleDef};
use crate::finding::Severity;

pub(crate) const WEAK_HASH_PY_DEF: RuleDef = RuleDef {
    id: "RULE-weak-hash-python",
    severity: Severity::Medium,
    message: "weak cryptographic hash (md5 or sha1) detected",
    languages: &[RulesLanguage::Python],
    matches: match_weak_hash,
};

pub(crate) const SHELL_INJECTION_PY_DEF: RuleDef = RuleDef {
    id: "RULE-shell-injection-python",
    severity: Severity::Critical,
    message: "subprocess call with shell=True detected",
    languages: &[RulesLanguage::Python],
    matches: match_shell_injection,
};

pub(crate) const UNSAFE_DESERIALIZATION_PY_DEF: RuleDef = RuleDef {
    id: "RULE-unsafe-deserialization-python",
    severity: Severity::High,
    message: "unsafe deserialization detected",
    languages: &[RulesLanguage::Python],
    matches: match_unsafe_deserialization,
};

/// `hashlib.md5(...)` / `hashlib.sha1(...)` with any arguments; matching
/// is name-based with no import resolution. Python attribute access is
/// case-sensitive (`hashlib.MD5` does not exist), so the names match
/// exactly, unlike the case-insensitive JavaScript hash rule.
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
    if function.kind() != "attribute" {
        return false;
    }
    let (Some(object), Some(attribute)) = (
        function.child_by_field_name("object"),
        function.child_by_field_name("attribute"),
    ) else {
        return false;
    };
    if object.kind() != "identifier" || text_of(source, object) != Some("hashlib") {
        return false;
    }
    attribute.kind() == "identifier" && matches!(text_of(source, attribute), Some("md5" | "sha1"))
}

/// Any `subprocess.<function>(...)` call carrying a `shell=True` keyword
/// argument. The boolean literal is its own node kind (`true` vs
/// `false`), so `shell=False` and a missing `shell` argument stay clean
/// without comparing value text.
fn match_shell_injection(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_call(root, |call| {
        if is_shell_true_call(source, call) {
            hits.push(Hit {
                start: call.start_byte(),
                end: call.end_byte(),
            });
        }
    });
    hits
}

fn is_shell_true_call(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "attribute" {
        return false;
    }
    let Some(object) = function.child_by_field_name("object") else {
        return false;
    };
    if object.kind() != "identifier" || text_of(source, object) != Some("subprocess") {
        return false;
    }
    let Some(arguments) = call.child_by_field_name("arguments") else {
        return false;
    };
    has_keyword_with_true_value(source, arguments, "shell")
}

/// Whether an `argument_list` holds a `keyword_argument` with the given
/// name whose value is the `true` literal node.
fn has_keyword_with_true_value(source: &[u8], arguments: tree_sitter::Node, name: &str) -> bool {
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|child| {
        if child.kind() != "keyword_argument" {
            return false;
        }
        let (Some(key), Some(value)) = (
            child.child_by_field_name("name"),
            child.child_by_field_name("value"),
        ) else {
            return false;
        };
        text_of(source, key) == Some(name) && value.kind() == "true"
    })
}

/// `pickle.load` / `pickle.loads` with any arguments, and `yaml.load`
/// without a `Loader=` keyword. Extra pickle arguments (such as
/// `encoding=`) do not make untrusted deserialization safe, so they do
/// not suppress the finding; `yaml.safe_load` never reaches this matcher
/// because its attribute name is not `load`.
fn match_unsafe_deserialization(source: &[u8], root: tree_sitter::Node) -> Vec<Hit> {
    let mut hits = Vec::new();
    each_call(root, |call| {
        if is_unsafe_deserialization_call(source, call) {
            hits.push(Hit {
                start: call.start_byte(),
                end: call.end_byte(),
            });
        }
    });
    hits
}

fn is_unsafe_deserialization_call(source: &[u8], call: tree_sitter::Node) -> bool {
    let Some(function) = call.child_by_field_name("function") else {
        return false;
    };
    if function.kind() != "attribute" {
        return false;
    }
    let (Some(object), Some(attribute)) = (
        function.child_by_field_name("object"),
        function.child_by_field_name("attribute"),
    ) else {
        return false;
    };
    if object.kind() != "identifier" || attribute.kind() != "identifier" {
        return false;
    }
    match text_of(source, object) {
        Some("pickle") => matches!(text_of(source, attribute), Some("load" | "loads")),
        Some("yaml") => {
            if text_of(source, attribute) != Some("load") {
                return false;
            }
            // A `Loader=` keyword selects the safe loader explicitly.
            let Some(arguments) = call.child_by_field_name("arguments") else {
                return true;
            };
            !has_keyword(source, arguments, "Loader")
        }
        _ => false,
    }
}

/// Whether an `argument_list` holds a `keyword_argument` with the given
/// name, regardless of its value.
fn has_keyword(source: &[u8], arguments: tree_sitter::Node, name: &str) -> bool {
    let mut cursor = arguments.walk();
    arguments.named_children(&mut cursor).any(|child| {
        if child.kind() != "keyword_argument" {
            return false;
        }
        let Some(key) = child.child_by_field_name("name") else {
            return false;
        };
        text_of(source, key) == Some(name)
    })
}

/// Visits every `call` node in document order with an explicit stack
/// rather than recursion, so hostile nesting cannot overflow the stack.
fn each_call(root: tree_sitter::Node, mut visit: impl FnMut(tree_sitter::Node)) {
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if node.kind() == "call" {
            visit(node);
        }
        let mut cursor = node.walk();
        let children: Vec<_> = node.named_children(&mut cursor).collect();
        stack.extend(children.into_iter().rev());
    }
}

fn text_of<'a>(source: &'a [u8], node: tree_sitter::Node) -> Option<&'a str> {
    node.utf8_text(source).ok()
}

#[cfg(test)]
mod tests {
    use crate::engine::rules::RulesEngine;
    use crate::finding::Severity;

    #[test]
    fn weak_hash_python_fires_with_pinned_id_and_severity() {
        let found = RulesEngine::new().scan("a.py", b"x = hashlib.md5(data)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash-python");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_python_fires_for_sha1_and_pyi_files() {
        let found = RulesEngine::new().scan("j.pyi", b"y = hashlib.sha1(chunk)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-weak-hash-python");
        assert_eq!(found[0].severity, Severity::Medium);
    }

    #[test]
    fn weak_hash_python_ignores_sha256() {
        let found = RulesEngine::new().scan("a.py", b"x = hashlib.sha256(data)");
        assert!(found.is_empty(), "got {found:?}");
    }

    #[test]
    fn shell_injection_python_fires_for_shell_true() {
        let found = RulesEngine::new().scan("a.py", b"subprocess.run(cmd, shell=True)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-shell-injection-python");
        assert_eq!(found[0].severity, Severity::Critical);
    }

    #[test]
    fn shell_injection_python_ignores_shell_false_and_missing_shell() {
        let engine = RulesEngine::new();
        assert!(
            engine
                .scan("a.py", b"subprocess.run(cmd, shell=False)")
                .is_empty()
        );
        assert!(engine.scan("a.py", b"subprocess.call(cmd)").is_empty());
    }

    #[test]
    fn unsafe_deserialization_python_fires_for_pickle_and_yaml_load() {
        let engine = RulesEngine::new();
        let found = engine.scan("a.py", b"pickle.loads(payload)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-unsafe-deserialization-python");
        assert_eq!(found[0].severity, Severity::High);
        let found = engine.scan("a.py", b"yaml.load(data)");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-unsafe-deserialization-python");
        assert_eq!(found[0].severity, Severity::High);
    }

    #[test]
    fn unsafe_deserialization_python_reports_pickle_loads_with_extra_arguments() {
        // Extra keyword arguments do not make untrusted deserialization
        // safe, so they must not suppress the finding.
        let found = RulesEngine::new().scan("a.py", b"pickle.loads(payload, encoding=\"latin1\")");
        assert_eq!(found.len(), 1);
        assert_eq!(found[0].rule_id, "RULE-unsafe-deserialization-python");
    }

    #[test]
    fn unsafe_deserialization_python_ignores_safe_yaml_forms() {
        let engine = RulesEngine::new();
        assert!(
            engine
                .scan("a.py", b"yaml.load(data, Loader=yaml.SafeLoader)")
                .is_empty()
        );
        assert!(engine.scan("a.py", b"yaml.safe_load(data)").is_empty());
    }

    #[test]
    fn python_rules_do_not_fire_on_javascript_files() {
        let found = RulesEngine::new().scan("a.js", b"hashlib.md5(data)");
        assert!(found.is_empty(), "got {found:?}");
    }

    #[test]
    fn javascript_rules_do_not_fire_on_python_files() {
        let found = RulesEngine::new().scan("a.py", b"eval(data)");
        assert!(found.is_empty(), "got {found:?}");
    }

    #[test]
    fn python_hit_spans_the_whole_call() {
        let found = RulesEngine::new().scan("a.py", b"x = hashlib.md5(data)");
        assert_eq!(found.len(), 1);
        assert_eq!((found[0].line, found[0].column), (1, 5));
    }
}
