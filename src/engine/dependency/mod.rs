pub mod map;
pub mod parse;
use crate::cache::XdgCache;
use crate::finding::{Diagnostic, Finding, Severity};
use crate::osv::client::{NETWORK_BUDGET, OsvApi, Query};
use crate::osv::validate;
#[allow(unused_imports)]
pub use parse::{Ecosystem, Pin};
use std::path::{Path, PathBuf};
use std::time::Instant;
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
                    } else if cache.as_ref().is_some_and(|c| {
                        c.entry_present(pin.ecosystem.as_str(), &pin.name, &pin.version)
                    }) {
                        diags.push(Diagnostic::cache_entry_corrupt(
                            &pin.path,
                            &format!(
                                "offline cache entry unreadable for {}@{}",
                                pin.name, pin.version
                            ),
                        ));
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
                    let deadline = Instant::now() + NETWORK_BUDGET;
                    match osv.query_all_with_deadline(&queries, deadline) {
                        Ok(results) if !results.is_empty() => {
                            for (pin, advs) in pending.iter().zip(results.iter()) {
                                if let Some(c) = cache.as_ref() {
                                    let vals: Vec<serde_json::Value> = advs
                                        .iter()
                                        .map(|adv| serde_json::json!({"id": adv.id, "summary": adv.summary, "severity": [{"type":"CVSS_V3","score": match adv.severity { Severity::Critical => "9.8", Severity::High => "7.5", Severity::Medium => "5.0", Severity::Low => "2.1" }}]}))
                                        .collect();
                                    if let Ok(b) = serde_json::to_vec(&vals) {
                                        let _ = c.put(
                                            pin.ecosystem.as_str(),
                                            &pin.name,
                                            &pin.version,
                                            &b,
                                        );
                                    }
                                }
                                for adv in advs {
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
        let r4 = tempfile::tempdir().unwrap();
        std::fs::write(r4.path().join("requirements.txt"), b"flask==2.3.3\n").unwrap();
        let (_, diags) = DependencyEngine::online(
            Some(XdgCache::with_root(
                tempfile::tempdir().unwrap().path().to_path_buf(),
            )),
            Box::new(FailOsv),
        )
        .review(r4.path(), &[PathBuf::from("requirements.txt")]);
        assert!(diags.iter().any(|d| d.code == "osv-unavailable"));
    }
    #[test]
    fn batch_results_stay_with_their_pin() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        std::fs::write(root.path().join("requirements.txt"), b"flask==2.3.3\n").unwrap();
        let stub = crate::osv::client::StubOsv::new(vec![(
            vec![
                serde_json::json!({"vulns":[{"id":"GHSA-A1","severity":[{"type":"CVSS_V3","score":"9.8"}]},{"id":"GHSA-A2","severity":[{"type":"CVSS_V3","score":"7.5"}]}]}),
                serde_json::json!({"vulns":[{"id":"GHSA-B1","severity":[{"type":"CVSS_V3","score":"5.0"}]}]}),
            ],
            None,
        )]);
        let cache = XdgCache::with_root(tempfile::tempdir().unwrap().path().to_path_buf());
        let (findings, _) = DependencyEngine::online(Some(cache), Box::new(stub)).review(
            root.path(),
            &[
                PathBuf::from("package-lock.json"),
                PathBuf::from("requirements.txt"),
            ],
        );
        assert_eq!(findings.len(), 3);
        for f in &findings {
            match f.rule_id.as_str() {
                "OSV-GHSA-A1" | "OSV-GHSA-A2" => {
                    assert_eq!(f.location.path, "package-lock.json")
                }
                "OSV-GHSA-B1" => assert_eq!(f.location.path, "requirements.txt"),
                other => panic!("unexpected rule {other}"),
            }
        }
    }
    struct FailOsv;
    impl crate::osv::client::OsvApi for FailOsv {
        fn query_all(
            &self,
            _qs: &[crate::osv::client::Query],
        ) -> Result<Vec<Vec<crate::osv::validate::Advisory>>, String> {
            Err("network failure".into())
        }
        fn vuln(&self, _id: &str) -> Result<crate::osv::validate::Advisory, String> {
            Err("network failure".into())
        }
    }
    struct StubRef(std::sync::Arc<crate::osv::client::StubOsv>);
    impl crate::osv::client::OsvApi for StubRef {
        fn query_all(
            &self,
            qs: &[crate::osv::client::Query],
        ) -> Result<Vec<Vec<crate::osv::validate::Advisory>>, String> {
            self.0.query_all(qs)
        }
        fn vuln(&self, id: &str) -> Result<crate::osv::validate::Advisory, String> {
            self.0.vuln(id)
        }
        fn query_all_with_deadline(
            &self,
            qs: &[crate::osv::client::Query],
            deadline: Instant,
        ) -> Result<Vec<Vec<crate::osv::validate::Advisory>>, String> {
            self.0.query_all_with_deadline(qs, deadline)
        }
        fn vuln_with_deadline(
            &self,
            id: &str,
            deadline: Instant,
        ) -> Result<crate::osv::validate::Advisory, String> {
            self.0.vuln_with_deadline(id, deadline)
        }
    }
    #[test]
    fn shared_budget_is_one_deadline() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        std::fs::write(root.path().join("requirements.txt"), b"flask==2.3.3\n").unwrap();
        let stub = std::sync::Arc::new(crate::osv::client::StubOsv::new(vec![(
            vec![
                serde_json::json!({"vulns":[{"id":"GHSA-C1","severity":[{"type":"CVSS_V3","score":"9.8"}]}]}),
                serde_json::json!({"vulns":[{"id":"GHSA-D1"}]}),
            ],
            None,
        )]));
        stub.set_detail(
            "GHSA-D1",
            crate::osv::validate::Advisory {
                id: "GHSA-D1".into(),
                summary: "detail".into(),
                severity: crate::finding::Severity::Medium,
            },
        );
        let before = Instant::now();
        let cache = XdgCache::with_root(tempfile::tempdir().unwrap().path().to_path_buf());
        let _ = DependencyEngine::online(Some(cache), Box::new(StubRef(stub.clone()))).review(
            root.path(),
            &[
                PathBuf::from("package-lock.json"),
                PathBuf::from("requirements.txt"),
            ],
        );
        let deadlines = stub.deadlines.lock().unwrap().clone();
        assert_eq!(deadlines.len(), 2);
        assert_eq!(deadlines[0], deadlines[1]);
        for d in &deadlines {
            assert!(*d >= before);
            assert!(*d <= Instant::now() + NETWORK_BUDGET);
        }
        let past = Instant::now() - std::time::Duration::from_secs(60);
        let q = Query {
            eco: "npm".into(),
            name: "a".into(),
            ver: "1".into(),
        };
        assert_eq!(
            stub.query_all_with_deadline(std::slice::from_ref(&q), past)
                .unwrap_err(),
            "network budget exceeded"
        );
        assert_eq!(
            stub.vuln_with_deadline("GHSA-C1", past).unwrap_err(),
            "network budget exceeded"
        );
    }
    #[test]
    fn warm_cache_repeats_every_advisory() {
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = XdgCache::with_root(cache_dir.path().to_path_buf());
        let stub_a = crate::osv::client::StubOsv::new(vec![(
            vec![
                serde_json::json!({"vulns":[{"id":"GHSA-A1","severity":[{"type":"CVSS_V3","score":"9.8"}]},{"id":"GHSA-A2","severity":[{"type":"CVSS_V3","score":"7.5"}]}]}),
            ],
            None,
        )]);
        let (cold, _) = DependencyEngine::online(Some(cache.clone()), Box::new(stub_a))
            .review(root.path(), &[PathBuf::from("package-lock.json")]);
        assert_eq!(cold.len(), 2);
        assert!(cold.iter().any(|f| f.rule_id == "OSV-GHSA-A1"));
        assert!(cold.iter().any(|f| f.rule_id == "OSV-GHSA-A2"));
        let empty = crate::osv::client::StubOsv::new(vec![]);
        let (warm, _) = DependencyEngine::online(Some(cache.clone()), Box::new(empty))
            .review(root.path(), &[PathBuf::from("package-lock.json")]);
        assert_eq!(warm.len(), 2);
        assert!(warm.iter().any(|f| f.rule_id == "OSV-GHSA-A1"));
        assert!(warm.iter().any(|f| f.rule_id == "OSV-GHSA-A2"));
        assert_eq!(warm, cold);
    }
    #[test]
    fn offline_corrupt_entry_reports_corruption_not_a_miss() {
        let cache_dir = tempfile::tempdir().unwrap();
        let cache = XdgCache::with_root(cache_dir.path().to_path_buf());
        let key = cache.entry_path("npm", "lodash", "4.17.20").unwrap();
        std::fs::create_dir_all(key.parent().unwrap()).unwrap();
        std::fs::write(&key, b"{ not json").unwrap();
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        let (findings, diags) = DependencyEngine::offline(Some(cache.clone()))
            .review(root.path(), &[PathBuf::from("package-lock.json")]);
        assert!(diags.iter().any(|d| d.code == "cache-entry-corrupt"));
        assert!(!diags.iter().any(|d| d.code == "osv-unavailable"));
        assert!(findings.is_empty());
        assert_eq!(std::fs::read(&key).unwrap(), b"{ not json");
        let big = vec![b'a'; 1024 * 1024 + 1];
        std::fs::write(&key, &big).unwrap();
        let (findings, diags) = DependencyEngine::offline(Some(cache))
            .review(root.path(), &[PathBuf::from("package-lock.json")]);
        assert!(diags.iter().any(|d| d.code == "cache-entry-corrupt"));
        assert!(!diags.iter().any(|d| d.code == "osv-unavailable"));
        assert!(findings.is_empty());
        assert_eq!(std::fs::read(&key).unwrap(), big);
    }
    #[test]
    fn offline_absent_entry_is_still_a_miss() {
        let cache = XdgCache::with_root(tempfile::tempdir().unwrap().path().to_path_buf());
        let root = tempfile::tempdir().unwrap();
        std::fs::write(
            root.path().join("package-lock.json"),
            r#"{"packages":{"node_modules/lodash":{"version":"4.17.20"}}}"#,
        )
        .unwrap();
        let (findings, diags) = DependencyEngine::offline(Some(cache))
            .review(root.path(), &[PathBuf::from("package-lock.json")]);
        assert!(findings.is_empty());
        assert!(diags.iter().any(|d| d.code == "osv-unavailable"));
        assert!(!diags.iter().any(|d| d.code == "cache-entry-corrupt"));
    }
}
