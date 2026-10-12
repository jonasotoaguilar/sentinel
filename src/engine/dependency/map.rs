//! Pin + fingerprint.
#![allow(dead_code)]
use crate::{
    engine::dependency::Pin,
    finding::{Finding, Location, Severity},
};
pub fn fingerprint(pin: &Pin, adv: &str) -> String {
    let mut pay = Vec::new();
    pay.extend_from_slice(pin.ecosystem.as_str().as_bytes());
    pay.push(0);
    pay.extend_from_slice(pin.name.as_bytes());
    pay.push(0);
    pay.extend_from_slice(pin.version.as_bytes());
    pay.push(0);
    pay.extend_from_slice(adv.as_bytes());
    let mut inp = Vec::with_capacity(8 + pay.len());
    inp.extend_from_slice(&(pay.len() as u64).to_le_bytes());
    inp.extend_from_slice(&pay);
    format!(
        "{}/OSV-{}/{}:{}:{}/{}",
        crate::engine::ENGINE_DEPENDENCY,
        adv,
        pin.path,
        pin.line,
        pin.column,
        blake3::hash(&inp).to_hex()
    )
}
pub fn to_finding(pin: &Pin, adv: &str, summary: &str, cvss: Option<f64>) -> Finding {
    let sev = match cvss {
        Some(s) if s >= 9.0 => Severity::Critical,
        Some(s) if s >= 7.0 => Severity::High,
        Some(s) if s >= 4.0 => Severity::Medium,
        Some(s) if s > 0.0 => Severity::Low,
        _ => Severity::High,
    };
    let mut ev: String = summary
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    if ev.len() > 4096 {
        ev.truncate(ev.floor_char_boundary(4096));
    }
    Finding {
        id: fingerprint(pin, adv),
        engine: crate::engine::ENGINE_DEPENDENCY.into(),
        rule_id: format!("OSV-{adv}"),
        severity: sev,
        location: Location {
            path: pin.path.clone(),
            line: pin.line,
            column: pin.column,
            snippet: format!("{}=={}", pin.name, pin.version),
        },
        message: format!(
            "{} {}@{} is affected by OSV-{}",
            pin.ecosystem, pin.name, pin.version, adv
        ),
        evidence: ev,
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::dependency::{Ecosystem, Pin};
    fn pl() -> Pin {
        Pin {
            ecosystem: Ecosystem::Npm,
            name: "lodash".into(),
            version: "4.17.20".into(),
            path: "package-lock.json".into(),
            line: 1,
            column: 1,
        }
    }
    fn pf() -> Pin {
        Pin {
            ecosystem: Ecosystem::PyPI,
            name: "flask".into(),
            version: "2.3.3".into(),
            path: "requirements.txt".into(),
            line: 5,
            column: 1,
        }
    }
    #[test]
    fn all() {
        let a = fingerprint(&pl(), "GHSA-abc");
        assert_eq!(a, fingerprint(&pl(), "GHSA-abc"));
        assert!(a.starts_with("dependency/OSV-GHSA-abc/package-lock.json:1:1/"));
        let f1 = to_finding(&pl(), "GHSA-123", "v", Some(9.8));
        let f2 = to_finding(&pf(), "PYSEC-456", "v", None);
        assert_eq!(f1.engine, "dependency");
        assert_eq!(f1.severity, Severity::Critical);
        assert_eq!(f2.severity, Severity::High);
        assert_eq!(
            to_finding(&pl(), "A", "s", Some(5.0)).severity,
            Severity::Medium
        );
        assert_eq!(crate::engine::ENGINE_DEPENDENCY, "dependency");
        assert!(
            to_finding(&pl(), "GHSA-x", &"a".repeat(5000), None)
                .evidence
                .len()
                <= 4096
        );
        let ev2 = to_finding(&pl(), "GHSA-x", &"🦀".repeat(2000), None).evidence;
        assert!(ev2.len() <= 4096 && ev2.len().is_multiple_of("🦀".len()));
        let m = format!("{}{}", "a".repeat(4095), "🦀");
        assert_eq!(to_finding(&pl(), "GHSA-x", &m, None).evidence.len(), 4095);
    }
}
