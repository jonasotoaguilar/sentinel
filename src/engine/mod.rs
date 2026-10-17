//! Detector engines; each redacts secret values at its own boundary
//! (ADR-0003), so only redacted fields and fixed digests leave the engine.

pub mod dependency;
pub mod rules;
pub mod secrets;

/// Stable engine identifier for the secrets detector; part of fingerprints.
pub const ENGINE: &str = "secrets";

/// Stable engine identifier for the dependency detector; part of fingerprints.
pub const ENGINE_DEPENDENCY: &str = "dependency";

/// Stable engine identifier for the code-rules detector; part of fingerprints.
#[allow(dead_code)] // Consumed by the rules wiring in the next work unit of this chain.
pub const ENGINE_RULES: &str = "rules";
