//! Opt-in advisory explanations (explain-adapter spec): an [`Explainer`] seam
//! for display-only terminal text that can never influence findings, severity,
//! ordering, or the exit code. [`http::HttpExplainer`] is the bounded
//! single-attempt adapter; nothing here performs I/O by itself.

use crate::finding::Finding;

pub mod http;
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

/// Why an explanation attempt yielded no advisories; the pipeline maps each
/// variant to its `explain-*` diagnostic and continues the scan unchanged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ExplainError {
    /// The request failed, timed out, or returned a non-success status.
    Failed(String),
    /// The body was unparseable or wrongly shaped.
    Invalid(String),
}

/// The advisory seam. The pipeline calls it at most once per scan, only when
/// `--explain` was requested and allowed; tests inject [`StubExplainer`].
pub trait Explainer {
    /// Whether the explainer can run. When false the pipeline emits exactly
    /// one `explain-skipped` diagnostic and never calls [`Explainer::explain`].
    fn is_configured(&self) -> bool;
    /// Returns advisory texts keyed by finding id. A failure degrades to the
    /// matching `explain-*` diagnostic, never to a retry or an exit change.
    fn explain(&self, findings: &[Finding]) -> Result<Vec<Explanation>, ExplainError>;
}

/// Unconfigured explainer (this unit: always; PR6 builds the HTTP adapter).
pub struct DisabledExplainer;

impl Explainer for DisabledExplainer {
    fn is_configured(&self) -> bool {
        false
    }
    fn explain(&self, _f: &[Finding]) -> Result<Vec<Explanation>, ExplainError> {
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
