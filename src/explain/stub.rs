//! Deterministic test double for [`Explainer`](super::Explainer): counts its
//! calls and answers with an injectable outcome. Never touches the network.

use std::sync::atomic::{AtomicUsize, Ordering};

use super::{Explainer, Explanation};
use crate::finding::Finding;

/// What the stub answers with: one advisory per finding (`PerFinding`), or a
/// canned list (`Fixed`) for hostile text and unknown ids.
enum StubOutcome {
    PerFinding(String),
    Fixed(Vec<Explanation>),
}

/// A recording [`Explainer`] for tests.
pub struct StubExplainer {
    calls: AtomicUsize,
    configured: bool,
    outcome: StubOutcome,
}

impl StubExplainer {
    /// A configured stub answering one advisory per finding.
    pub fn per_finding(prefix: &str) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            configured: true,
            outcome: StubOutcome::PerFinding(prefix.to_string()),
        }
    }

    /// A configured stub replaying a canned response list.
    pub fn fixed(explanations: Vec<Explanation>) -> Self {
        Self {
            calls: AtomicUsize::new(0),
            configured: true,
            outcome: StubOutcome::Fixed(explanations),
        }
    }

    /// How many times the pipeline invoked the stub.
    pub fn calls(&self) -> usize {
        self.calls.load(Ordering::SeqCst)
    }
}

impl Explainer for StubExplainer {
    fn is_configured(&self) -> bool {
        self.configured
    }

    fn explain(&self, findings: &[Finding]) -> Result<Vec<Explanation>, String> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        match &self.outcome {
            StubOutcome::PerFinding(prefix) => Ok(findings
                .iter()
                .map(|finding| Explanation {
                    finding_id: finding.id.clone(),
                    text: format!("{prefix}{}", finding.id),
                })
                .collect()),
            StubOutcome::Fixed(explanations) => Ok(explanations.clone()),
        }
    }
}
