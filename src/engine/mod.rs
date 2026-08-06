//! Detector engines; each redacts secret values at its own boundary
//! (ADR-0003), so only redacted fields and fixed digests leave the engine.

pub mod secrets;

/// Stable engine identifier for the secrets detector; part of fingerprints.
pub const ENGINE: &str = "secrets";
