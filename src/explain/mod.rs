//! Opt-in advisory explanations (explain-adapter spec): an [`Explainer`] seam
//! for display-only terminal text that can never influence findings, severity,
//! ordering, or the exit code. The bounded HTTP adapter is the next unit, so
//! nothing here performs I/O.

use crate::finding::Finding;

pub mod stub;

pub use stub::StubExplainer;

/// Advisory text for one finding; unknown ids are ignored by the pipeline.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Explanation {
    /// The [`Finding::id`] the text belongs to.
    pub finding_id: String,
    /// Untrusted model text; sanitized before rendering.
    pub text: String,
}

/// The advisory seam. The pipeline calls it at most once per scan, only when
/// `--explain` was requested and allowed; tests inject [`StubExplainer`].
pub trait Explainer {
    /// Whether the explainer can run. When false the pipeline emits exactly
    /// one `explain-skipped` diagnostic and never calls [`Explainer::explain`].
    fn is_configured(&self) -> bool;
    /// Returns advisory texts keyed by finding id, or an error message when
    /// the adapter fails (the scan then continues without advisories).
    fn explain(&self, findings: &[Finding]) -> Result<Vec<Explanation>, String>;
}

/// Unconfigured explainer (this unit: always; PR6 builds the HTTP adapter).
pub struct DisabledExplainer;

impl Explainer for DisabledExplainer {
    fn is_configured(&self) -> bool {
        false
    }
    fn explain(&self, _f: &[Finding]) -> Result<Vec<Explanation>, String> {
        Ok(Vec::new())
    }
}
/// Sanitizes untrusted advisory text to one terminal-safe line: controls
/// dropped, newline runs collapsed to a space, trimmed, capped at 500 chars.
/// The renderer adds the `advice:` prefix, so text can never forge a finding.
pub(crate) fn sanitize_advisory(text: &str) -> String {
    let mut out = String::new();
    let mut pending_space = false;
    for c in text.chars() {
        if c == '\n' || c == '\r' || c == '\t' {
            pending_space = true;
        } else if c.is_control() {
            // Dropped: ANSI escapes and other terminal control sequences.
        } else {
            if pending_space {
                out.push(' ');
            }
            pending_space = false;
            out.push(c);
        }
    }
    out.trim().chars().take(500).collect()
}
