pub mod map;
pub mod parse;
use crate::cache::XdgCache;
use crate::finding::{Diagnostic, Finding, Severity};
use crate::osv::client::{OsvApi, Query};
use crate::osv::validate;
#[allow(unused_imports)]
pub use parse::{Ecosystem, Pin};
use std::path::{Path, PathBuf};
pub enum Transport {
    Offline(Option<XdgCache>),
    Online(Option<XdgCache>, Box<dyn OsvApi>),
}
pub struct DependencyEngine {
    transport: Transport,
}
impl DependencyEngine {
    pub fn offline(c: Option<XdgCache>) -> Self {
        Self {
            transport: Transport::Offline(c),
        }
    }
    pub fn online(c: Option<XdgCache>, osv: Box<dyn OsvApi>) -> Self {
        Self {
            transport: Transport::Online(c, osv),
        }
    }
    pub fn review(&self, root: &Path, files: &[PathBuf]) -> (Vec<Finding>, Vec<Diagnostic>) {
        let mut diags = Vec::new();
        let mut pins = Vec::new();
        for rel in files {
            let p = rel.to_string_lossy().replace('\\', "/");
            let b = match std::fs::read(root.join(rel)) {
                Ok(b) => b,
                Err(e) => {
                    diags.push(Diagnostic::read_failed(&p, &e));
                    continue;
                }
            };
            let (mut pp, mut dd) = parse::parse_file(&p, &b);
            pins.append(&mut pp);
            diags.append(&mut dd);
        }
        pins.sort();
        pins.dedup();
        let mut out = Vec::new();
        match &self.transport {
            Transport::Offline(cache) => {
                for pin in &pins {
                    let hit = cache.as_ref().and_then(|c| {
                        c.get_offline(pin.ecosystem.as_str(), &pin.name, &pin.version)
                    });
                    if let Some(b) = hit {
                        handle_cached(&b, pin, &mut diags, &mut out);
                    } else {
                        diags.push(Diagnostic::osv_unavailable(
                            &pin.path,
                            &format!("offline cache miss for {}@{}", pin.name, pin.version),
                        ));
                    }
                }
            }
            Transport::Online(cache, osv) => {
                let mut pending = Vec::new();
                for pin in &pins {
                    let hit = cache
                        .as_ref()
                        .and_then(|c| c.get(pin.ecosystem.as_str(), &pin.name, &pin.version));
                    if let Some(b) = hit {
                        if !handle_cached(&b, pin, &mut diags, &mut out) {
                            pending.push(pin);
                        }
                    } else {
                        pending.push(pin);
                    }
                }
                if !pending.is_empty() {
                    let queries: Vec<Query> = pending
                        .iter()
                        .map(|p| Query {
                            eco: p.ecosystem.as_str().into(),
                            name: p.name.clone(),
                            ver: p.version.clone(),
                        })
                        .collect();
                    match osv.query_all(&queries) {
                        Ok(advs) if !advs.is_empty() => {
                            for (pin, adv) in pending.iter().zip(advs.iter()) {
                                if let Some(c) = cache.as_ref() {
                                    let vals = vec![
                                        serde_json::json!({"id": adv.id, "summary": adv.summary, "severity": [{"type":"CVSS_V3","score": match adv.severity { Severity::Critical => "9.8", Severity::High => "7.5", Severity::Medium => "5.0", Severity::Low => "2.1" }}]}),
                                    ];
                                    if let Ok(b) = serde_json::to_vec(&vals) {
                                        let _ = c.put(
                                            pin.ecosystem.as_str(),
                                            &pin.name,
                                            &pin.version,
                                            &b,
                                        );
                                    }
                                }
                                out.push(map::to_finding(
                                    pin,
                                    &adv.id,
                                    &adv.summary,
                                    cvss(adv.severity),
                                ));
                            }
                            if advs.len() > pending.len() {
                                for adv in advs.iter().skip(pending.len()) {
                                    let pin = pending.last().unwrap();
                                    out.push(map::to_finding(
                                        pin,
                                        &adv.id,
                                        &adv.summary,
                                        cvss(adv.severity),
                                    ));
                                }
                            }
                        }
                        Ok(_) => {}
                        Err(e) => {
                            let san = crate::finding::sanitize(&e);
                            for pin in &pending {
                                let stale = cache.as_ref().and_then(|c| {
                                    c.get_offline(pin.ecosystem.as_str(), &pin.name, &pin.version)
                                });
                                if let Some(b) = stale {
                                    if handle_cached(&b, pin, &mut diags, &mut out) {
                                        diags.push(Diagnostic::osv_degraded(&san));
                                    } else {
                                        diags.push(Diagnostic::cache_entry_corrupt(
                                            &pin.path,
                                            "stale cache corrupt",
                                        ));
                                        diags.push(Diagnostic::osv_unavailable(&pin.path, &san));
                                    }
                                } else {
                                    diags.push(Diagnostic::osv_unavailable(&pin.path, &san));
                                }
                            }
                        }
                    }
                }
            }
        }
        out.sort();
        diags.sort();
        (out, diags)
    }
}
fn cvss(s: Severity) -> Option<f64> {
    match s {
        Severity::Critical => Some(9.8),
        Severity::High => Some(7.5),
        Severity::Medium => Some(5.0),
        Severity::Low => Some(2.1),
    }
}
fn handle_cached(b: &[u8], pin: &Pin, diags: &mut Vec<Diagnostic>, out: &mut Vec<Finding>) -> bool {
    if b.len() > 1024 * 1024 {
        diags.push(Diagnostic::cache_entry_corrupt(
            &pin.path,
            "cached entry too large",
        ));
        return false;
    }
    let v = match serde_json::from_slice::<serde_json::Value>(b) {
        Ok(v) => v,
        Err(_) => {
            diags.push(Diagnostic::cache_entry_corrupt(
                &pin.path,
                "cache entry corrupt",
            ));
            return false;
        }
    };
    let vals = if let Some(a) = v.as_array() {
        a.clone()
    } else {
        vec![v]
    };
    let mut emitted = false;
    for vv in vals {
        match validate::validate_advisory(&vv) {
            Ok(Some(ad)) => {
                out.push(map::to_finding(pin, &ad.id, &ad.summary, cvss(ad.severity)));
                emitted = true;
            }
            Ok(None) => emitted = true,
            Err(e) => diags.push(Diagnostic::advisory_invalid(&crate::finding::sanitize(
                &e.message,
            ))),
        }
    }
    emitted
}
#[cfg(test)]
mod tests {
    use super::*;
    use crate::cache::XdgCache;
    use std::path::PathBuf;
    #[test]
    fn all() {
        let b = crate::osv::client::constructions();
        assert!(
            DependencyEngine::offline(Some(XdgCache::with_root(
                tempfile::tempdir().unwrap().path().to_path_buf()
            )))
            .review(tempfile::tempdir().unwrap().path(), &[])
            .0
            .is_empty()
        );
        assert!(crate::osv::client::UreqOsvClient::maybe_new(true).is_none());
        assert_eq!(crate::osv::client::constructions(), b);
        let c2 = XdgCache::with_root(tempfile::tempdir().unwrap().path().to_path_buf());
        c2.put("npm", "lodash", "4.17.20", &serde_json::to_vec(&serde_json::json!({"id":"GHSA-1234","summary":"t","severity":[{"type":"CVSS_V3","score":"9.8"}]})).unwrap()).unwrap();
        let r = tempfile::tempdir().unwrap();
        std::fs::write(
            r.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        assert_eq!(
            DependencyEngine::offline(Some(c2))
                .review(r.path(), &[PathBuf::from("package-lock.json")])
                .0[0]
                .rule_id,
            "OSV-GHSA-1234"
        );
        let r3 = tempfile::tempdir().unwrap();
        std::fs::write(
            r3.path().join("requirements.txt"),
            b"flask==2.3.3
",
        )
        .unwrap();
        assert!(
            DependencyEngine::offline(Some(XdgCache::with_root(
                tempfile::tempdir().unwrap().path().to_path_buf()
            )))
            .review(r3.path(), &[PathBuf::from("requirements.txt")])
            .1
            .iter()
            .any(|d| d.code == "osv-unavailable")
        );
    }
}
