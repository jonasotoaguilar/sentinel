use crate::finding::{Diagnostic, Severity};
use serde_json::Value;
const MAX_BODY: usize = 1 << 20;
const MAX_SUM: usize = 4096;
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Advisory {
    pub id: String,
    pub summary: String,
    pub severity: Severity,
}
pub fn check_size(b: &[u8]) -> Result<(), Diagnostic> {
    if b.len() > MAX_BODY {
        Err(Diagnostic {
            code: "advisory-invalid",
            path: String::new(),
            rule: String::new(),
            message: "response too large".into(),
        })
    } else {
        Ok(())
    }
}
pub fn is_valid_id(id: &str) -> bool {
    if id.is_empty() || id.len() > 128 || id.contains('/') || id.contains('\\') || id.contains('\0')
    {
        return false;
    }
    let l = id.to_ascii_lowercase();
    if l.contains("..") || l.contains("<script") || l == "nan" {
        return false;
    }
    let mut c = id.chars();
    match c.next() {
        Some(x) if x.is_ascii_uppercase() => {}
        _ => return false,
    }
    for ch in c {
        if !matches!(ch,'A'..='Z'|'0'..='9'|':'|'.'|'_'|'-') {
            return false;
        }
    }
    true
}
/// Bounds an advisory summary: drops control characters except newline and tab,
/// then caps at MAX_SUM bytes on a character boundary. Guarantees bounded,
/// control-stripped text; it does not redact secrets and does not make the
/// text single-line or terminal-safe.
pub fn sanitize_summary(s: &str) -> String {
    let mut t: String = s
        .chars()
        .filter(|c| !c.is_control() || *c == '\n' || *c == '\t')
        .collect();
    if t.len() > MAX_SUM {
        t.truncate(t.floor_char_boundary(MAX_SUM));
    }
    t
}
/// Maps a CVSS score to a severity: the single source every severity site reads
/// (dependency findings delegate here, so the thresholds cannot drift). A missing
/// score, or one at or below zero, maps to High; callers disclose that guess with
/// an advisory-severity-fallback diagnostic at their own site, never here.
pub fn severity_for(cvss: Option<f64>) -> Severity {
    match cvss {
        Some(v) if v >= 9.0 => Severity::Critical,
        Some(v) if v >= 7.0 => Severity::High,
        Some(v) if v >= 4.0 => Severity::Medium,
        Some(v) if v > 0.0 => Severity::Low,
        _ => Severity::High,
    }
}
/// Canonical representative CVSS score for a severity: the single inverse of
/// [`severity_for`], so every Severity-to-score site reads this one table.
/// Guarantees the fixed representatives Critical 9.8, High 7.5, Medium 5.0,
/// Low 2.1; it never derives a score from advisory data.
pub fn cvss_for_severity(severity: Severity) -> f64 {
    match severity {
        Severity::Critical => 9.8,
        Severity::High => 7.5,
        Severity::Medium => 5.0,
        Severity::Low => 2.1,
    }
}
fn is_vector_score(s: &str) -> bool {
    for p in ["CVSS:3.0/", "CVSS:3.1/", "CVSS:4.0/"] {
        if let Some(rest) = s.strip_prefix(p) {
            if rest.is_empty() {
                return false;
            }
            return rest
                .split('/')
                .all(|seg| !seg.is_empty() && seg.contains(':'));
        }
    }
    false
}
fn roundup(v: f64) -> f64 {
    let scaled = (v * 100000.0).round() as i64;
    if scaled % 10000 == 0 {
        scaled as f64 / 100000.0
    } else {
        (scaled / 10000 + 1) as f64 / 10.0
    }
}
fn cvss3_base(vector: &str) -> Option<f64> {
    let rest = vector
        .strip_prefix("CVSS:3.1/")
        .or_else(|| vector.strip_prefix("CVSS:3.0/"))?;
    let mut av: Option<f64> = None;
    let mut ac: Option<f64> = None;
    let mut pr: Option<&str> = None;
    let mut ui: Option<f64> = None;
    let mut changed: Option<bool> = None;
    let mut c: Option<f64> = None;
    let mut integ: Option<f64> = None;
    let mut avail: Option<f64> = None;
    for part in rest.split('/') {
        let (k, val) = part.split_once(':')?;
        match k {
            "AV" => {
                av = Some(match val {
                    "N" => 0.85,
                    "A" => 0.62,
                    "L" => 0.55,
                    "P" => 0.2,
                    _ => return None,
                })
            }
            "AC" => {
                ac = Some(match val {
                    "L" => 0.77,
                    "H" => 0.44,
                    _ => return None,
                })
            }
            "PR" => pr = Some(val),
            "UI" => {
                ui = Some(match val {
                    "N" => 0.85,
                    "R" => 0.62,
                    _ => return None,
                })
            }
            "S" => {
                changed = Some(match val {
                    "U" => false,
                    "C" => true,
                    _ => return None,
                })
            }
            "C" => {
                c = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return None,
                })
            }
            "I" => {
                integ = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return None,
                })
            }
            "A" => {
                avail = Some(match val {
                    "N" => 0.0,
                    "L" => 0.22,
                    "H" => 0.56,
                    _ => return None,
                })
            }
            _ => {}
        }
    }
    let (av, ac, praw, ui, changed, c, integ, avail) =
        (av?, ac?, pr?, ui?, changed?, c?, integ?, avail?);
    let pr = match praw {
        "N" => 0.85,
        "L" if changed => 0.68,
        "L" => 0.62,
        "H" if changed => 0.5,
        "H" => 0.27,
        _ => return None,
    };
    let iss = 1.0 - (1.0 - c) * (1.0 - integ) * (1.0 - avail);
    let impact = if changed {
        7.52 * (iss - 0.029) - 3.25 * (iss - 0.02).powi(15)
    } else {
        6.42 * iss
    };
    if impact <= 0.0 {
        return Some(0.0);
    }
    let exploit = 8.22 * av * ac * pr * ui;
    let base = if changed {
        (1.08 * (impact + exploit)).min(10.0)
    } else {
        (impact + exploit).min(10.0)
    };
    Some(roundup(base))
}
fn cvss_score(v: &Value) -> Option<f64> {
    let arr = v.get("severity").and_then(|s| s.as_array())?;
    let mut max: Option<f64> = None;
    for e in arr {
        let Some(s) = e.get("score").and_then(|x| x.as_str()) else {
            continue;
        };
        let f = if let Ok(n) = s.parse::<f64>() {
            Some(n)
        } else {
            cvss3_base(s)
        };
        if let Some(f) = f {
            max = Some(max.map_or(f, |m: f64| m.max(f)));
        }
    }
    max
}
pub fn is_withdrawn(v: &Value) -> bool {
    v.get("withdrawn").is_some_and(|x| !x.is_null())
}
fn is_valid_rfc3339(s: &str) -> bool {
    let b = s.as_bytes();
    if b.len() < 20 {
        return false;
    }
    let dig = |i: usize| b.get(i).is_some_and(|c| c.is_ascii_digit());
    for i in [0, 1, 2, 3, 5, 6, 8, 9, 11, 12, 14, 15, 17, 18] {
        if !dig(i) {
            return false;
        }
    }
    if b[4] != b'-' || b[7] != b'-' || b[10] != b'T' || b[13] != b':' || b[16] != b':' {
        return false;
    }
    let num = |a: usize, n: usize| {
        b[a..a + n]
            .iter()
            .fold(0u32, |x, y| (x * 10) + (y - b'0') as u32)
    };
    let (mo, dy, hr, mi, se) = (num(5, 2), num(8, 2), num(11, 2), num(14, 2), num(17, 2));
    if !(1..=12).contains(&mo) || dy < 1 || hr > 23 || mi > 59 || se > 60 {
        return false;
    }
    let yr = num(0, 4);
    let leap = (yr % 4 == 0 && yr % 100 != 0) || yr % 400 == 0;
    if dy
        > match mo {
            1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
            4 | 6 | 9 | 11 => 30,
            _ => {
                if leap {
                    29
                } else {
                    28
                }
            }
        }
    {
        return false;
    }
    let mut i = 19;
    if b.get(i) == Some(&b'.') {
        i += 1;
        let s = i;
        while dig(i) {
            i += 1;
        }
        if i == s {
            return false;
        }
    }
    match b.get(i) {
        Some(b'Z') => i + 1 == b.len(),
        Some(b'+') | Some(b'-') => {
            i += 1;
            if !dig(i) || !dig(i + 1) {
                return false;
            }
            let oh = num(i, 2);
            i += 2;
            if b.get(i) != Some(&b':') {
                return false;
            }
            i += 1;
            if !dig(i) || !dig(i + 1) {
                return false;
            }
            let om = num(i, 2);
            oh <= 23 && om <= 59 && i + 2 == b.len()
        }
        _ => false,
    }
}
fn severity_ok(v: &Value) -> bool {
    match v.get("severity") {
        None => true,
        Some(s) => {
            let Some(arr) = s.as_array() else {
                return false;
            };
            for e in arr {
                let Some(o) = e.as_object() else {
                    return false;
                };
                let Some(sc) = o.get("score").and_then(|x| x.as_str()) else {
                    return false;
                };
                if sc.parse::<f64>().is_err() && !is_vector_score(sc) {
                    return false;
                }
            }
            true
        }
    }
}
fn affected_ok(v: &Value, detail: bool) -> bool {
    let Some(a) = v.get("affected") else {
        return !detail;
    };
    let Some(arr) = a.as_array() else {
        return false;
    };
    if detail && arr.is_empty() {
        return false;
    }
    let mut ours = false;
    for e in arr {
        let Some(o) = e.as_object() else {
            return false;
        };
        if let Some(p) = o.get("package") {
            let Some(po) = p.as_object() else {
                return false;
            };
            if let Some(ec) = po.get("ecosystem") {
                let Some(s) = ec.as_str() else {
                    return false;
                };
                if s == "npm" || s == "PyPI" {
                    ours = true;
                }
            }
        }
        for k in ["versions", "ranges"] {
            if let Some(x) = o.get(k)
                && x.as_array().is_none()
            {
                return false;
            }
        }
    }
    if detail && !ours {
        return false;
    }
    true
}
fn ts_ok(v: &Value, k: &str) -> bool {
    match v.get(k) {
        None => true,
        Some(x) if x.is_null() => true,
        Some(x) => x.as_str().is_some_and(is_valid_rfc3339),
    }
}
fn validate(v: &Value, detail: bool) -> Result<Option<Advisory>, Diagnostic> {
    let f = |m: &str| Diagnostic {
        code: "advisory-invalid",
        path: String::new(),
        rule: String::new(),
        message: m.into(),
    };
    if let Some(w) = v.get("withdrawn")
        && !w.is_null()
    {
        if w.as_str().is_none_or(|s| !is_valid_rfc3339(s)) {
            return Err(f("advisory-invalid"));
        }
        return Ok(None);
    }
    let id = v
        .get("id")
        .and_then(|x| x.as_str())
        .ok_or_else(|| f("advisory-invalid"))?;
    if !is_valid_id(id) {
        return Err(f("advisory-invalid"));
    }
    if !severity_ok(v) || !affected_ok(v, detail) || !ts_ok(v, "modified") || !ts_ok(v, "published")
    {
        return Err(f("advisory-invalid"));
    }
    let raw = v.get("summary").and_then(|x| x.as_str()).unwrap_or("");
    let summary = sanitize_summary(raw);
    let sev = severity_for(cvss_score(v));
    Ok(Some(Advisory {
        id: id.into(),
        summary,
        severity: sev,
    }))
}
pub fn validate_advisory(v: &Value) -> Result<Option<Advisory>, Diagnostic> {
    validate(v, false)
}
pub fn validate_advisory_detail(v: &Value) -> Result<Option<Advisory>, Diagnostic> {
    validate(v, true)
}
#[cfg(test)]
mod tests {
    use super::*;
    fn no_leak(d: &Diagnostic, raw: &str) {
        assert!(
            !d.message.contains(raw) && !d.message.contains("<script") && !d.message.contains("..")
        )
    }
    #[test]
    fn malformed_ids_rejected_canonical_accepted() {
        for bad in [
            "",
            "lowercase",
            "GHSA/abc",
            "GHSA\\abc",
            &"A".repeat(129),
            "../etc/passwd",
            "<script>alert(1)</script>",
            "nan",
            "GHSA-abc/../x",
        ] {
            assert!(!is_valid_id(bad), "{bad}");
        }
        assert!(is_valid_id("GHSA-1234-5678-9012"));
        assert!(is_valid_id("CVE-2023-1234"));
        assert!(is_valid_id("PYSEC-2023-1"));
    }
    #[test]
    fn invalid_id_never_leaks() {
        let v = validate_advisory(
            &serde_json::json!({"id":"GHSA-1234","summary":"<script>x</script>"}),
        );
        assert!(v.is_ok() && v.unwrap().is_some());
        let bad2 = serde_json::json!({"id":"<script>","summary":"x"});
        let e = validate_advisory(&bad2).unwrap_err();
        no_leak(&e, "<script>");
        let e2 = validate_advisory(&serde_json::json!({"id":"../etc/passwd"}));
        assert!(e2.is_err());
        no_leak(&e2.unwrap_err(), "../");
        assert!(validate_advisory(&serde_json::json!({"id":"nan"})).is_err());
    }
    #[test]
    fn withdrawn_state_preserved() {
        assert!(
            validate_advisory(
                &serde_json::json!({"id":"GHSA-123","withdrawn":"2023-01-01T00:00:00Z"})
            )
            .unwrap()
            .is_none()
        );
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-123","withdrawn":null}))
                .unwrap()
                .is_some()
        );
    }
    #[test]
    fn cvss_score_maps_to_severity() {
        for (cvss, exp) in [
            (Some(9.8), Severity::Critical),
            (Some(7.5), Severity::High),
            (Some(5.0), Severity::Medium),
            (Some(2.1), Severity::Low),
            (None, Severity::High),
        ] {
            assert_eq!(severity_for(cvss), exp);
        }
        let vuln = serde_json::json!({"id":"GHSA-1","severity":[{"type":"CVSS_V3","score":"9.8"}]});
        assert_eq!(cvss_score(&vuln), Some(9.8));
        let adv = validate_advisory(&vuln).unwrap().unwrap();
        assert_eq!(adv.severity, Severity::Critical);
        let adv2 = validate_advisory(
            &serde_json::json!({"id":"GHSA-2","severity":[{"type":"CVSS_V3","score":"2.1"}]}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(adv2.severity, Severity::Low);
        let miss = validate_advisory(&serde_json::json!({"id":"GHSA-3"}))
            .unwrap()
            .unwrap();
        assert_eq!(miss.severity, Severity::High);
    }
    #[test]
    fn oversize_responses_and_summaries_are_bounded() {
        assert!(check_size(&vec![b'a'; MAX_BODY + 1]).is_err());
        assert!(check_size(&vec![b'a'; MAX_BODY]).is_ok());
        let big = "a".repeat(5000);
        let adv3 = validate_advisory(&serde_json::json!({"id":"GHSA-4","summary":big}))
            .unwrap()
            .unwrap();
        assert!(adv3.summary.len() <= 4096);
        let ml = "🦀".repeat(2000);
        let adv4 = validate_advisory(&serde_json::json!({"id":"GHSA-5","summary":ml}))
            .unwrap()
            .unwrap();
        assert!(adv4.summary.len() <= 4096 && adv4.summary.len().is_multiple_of("🦀".len()));
    }
    #[test]
    fn boundary() {
        for eco in ["Go", "cargo", "RubyGems"] {
            let e = validate_advisory(
                &serde_json::json!({"id":"GHSA-10","affected":[{"package":{"ecosystem":eco}}]}),
            );
            assert!(e.unwrap().is_some(), "eco {eco}");
        }
        for eco in ["npm", "PyPI"] {
            let o = validate_advisory(
                &serde_json::json!({"id":"GHSA-11","affected":[{"package":{"ecosystem":eco}}]}),
            );
            assert!(o.unwrap().is_some(), "eco {eco}");
        }
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-12","affected":{"package":{}}}))
                .is_err()
        );
        assert!(validate_advisory(&serde_json::json!({"id":"GHSA-13","affected":["x"]})).is_err());
        assert!(validate_advisory(&serde_json::json!({"id":"GHSA-13B","affected":[{"package":{"ecosystem":"npm"},"versions":"1.0"}]})).is_err());
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-13C","affected":[{"package":"npm"}]}))
                .is_err()
        );
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-14","modified":"yesterday"})).is_err()
        );
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-14B","published":"not-a-time"}))
                .is_err()
        );
        for ts in ["2026-01-02T03:04:05Z", "2026-01-02T03:04:05.123+00:00"] {
            assert!(
                validate_advisory(&serde_json::json!({"id":"GHSA-15","modified":ts}))
                    .unwrap()
                    .is_some(),
                "{ts}"
            );
        }
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-16"}))
                .unwrap()
                .is_some()
        );
        assert!(validate_advisory(&serde_json::json!({"id":"GHSA-17","withdrawn":true})).is_err());
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-17B","withdrawn":"yesterday"}))
                .is_err()
        );
        assert!(
            validate_advisory(
                &serde_json::json!({"id":"GHSA-18","withdrawn":"2023-01-01T00:00:00Z"})
            )
            .unwrap()
            .is_none()
        );
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-19","severity":{"score":"9.8"}}))
                .is_err()
        );
        assert!(
            validate_advisory(&serde_json::json!({"id":"GHSA-20","severity":[{"type":"CVSS_V3"}]}))
                .is_err()
        );
        assert!(
            validate_advisory(
                &serde_json::json!({"id":"GHSA-20B","severity":[{"type":"CVSS_V3","score":"high"}]})
            )
            .is_err()
        );
        assert!(
            validate_advisory(
                &serde_json::json!({"id":"GHSA-20C","severity":[{"type":"CVSS_V3","score":9.8}]})
            )
            .is_err()
        );
        let ok = validate_advisory(
            &serde_json::json!({"id":"GHSA-21","severity":[{"type":"CVSS_V3","score":"9.8"}]}),
        )
        .unwrap()
        .unwrap();
        assert_eq!(ok.severity, Severity::Critical);
    }
    #[test]
    fn detail() {
        assert!(validate_advisory_detail(&serde_json::json!({"id":"GHSA-30"})).is_err());
        let o = validate_advisory_detail(
            &serde_json::json!({"id":"GHSA-31","affected":[{"package":{"ecosystem":"npm"}}]}),
        );
        assert!(o.unwrap().is_some());
        assert!(
            validate_advisory_detail(
                &serde_json::json!({"id":"GHSA-31B","affected":[{"package":{"ecosystem":"PyPI"}}]})
            )
            .unwrap()
            .is_some()
        );
        assert!(
            validate_advisory_detail(
                &serde_json::json!({"id":"GHSA-32","affected":[{"package":{"ecosystem":"cargo"}}]})
            )
            .is_err()
        );
        assert!(
            validate_advisory_detail(&serde_json::json!({"id":"GHSA-33","affected":[]})).is_err()
        );
        assert!(
            validate_advisory_detail(
                &serde_json::json!({"id":"GHSA-34","affected":[{"package":{}}]})
            )
            .is_err()
        );
    }
    #[test]
    fn wire_severity() {
        let d = validate_advisory_detail(
            &serde_json::json!({"id":"GHSA-41","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],"affected":[{"package":{"ecosystem":"npm"}}]}),
        );
        assert_eq!(d.unwrap().unwrap().severity, Severity::Medium);
    }
    #[test]
    fn wire_ecosystems() {
        assert!(
            validate_advisory(
                &serde_json::json!({"id":"GHSA-40","modified":"2025-09-29T21:12:31.102523Z"})
            )
            .unwrap()
            .is_some()
        );
        let d = validate_advisory_detail(
            &serde_json::json!({"id":"GHSA-42","severity":[{"type":"CVSS_V3","score":"5.0"}],"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[]},{"package":{"name":"lodash","ecosystem":"RubyGems"},"ranges":[]}]}),
        );
        assert!(d.unwrap().is_some());
        assert!(validate_advisory_detail(&serde_json::json!({"id":"GHSA-43","affected":[{"package":{"ecosystem":"RubyGems"}}]})).is_err());
    }
    #[test]
    fn vectors() {
        for (vec, score, sev) in [
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                9.8,
                Severity::Critical,
            ),
            (
                "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L",
                5.3,
                Severity::Medium,
            ),
            (
                "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:H/A:H",
                7.4,
                Severity::High,
            ),
            (
                "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
                6.1,
                Severity::Medium,
            ),
        ] {
            let v = serde_json::json!({"severity":[{"type":"CVSS_V3","score":vec}]});
            assert_eq!(cvss_score(&v), Some(score), "{vec}");
            let adv = validate_advisory(
                &serde_json::json!({"id":"GHSA-50","severity":[{"type":"CVSS_V3","score":vec}]}),
            );
            assert_eq!(adv.unwrap().unwrap().severity, sev, "{vec}");
        }
        assert!(validate_advisory(&serde_json::json!({"id":"GHSA-51","severity":[{"type":"CVSS_V3","score":"CVSS:2.0/AV:N/AC:L/Au:N/C:N/I:N/A:C"}]})).is_err());
        let v4 = serde_json::json!({"severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:NONE/SI:NONE/SA:NONE"}]});
        assert_eq!(cvss_score(&v4), None);
        let a4 = validate_advisory(
            &serde_json::json!({"id":"GHSA-52","severity":[{"type":"CVSS_V4","score":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:L/SC:NONE/SI:NONE/SA:NONE"}]}),
        );
        assert_eq!(a4.unwrap().unwrap().severity, Severity::High);
        let d = validate_advisory_detail(
            &serde_json::json!({"id":"GHSA-53","modified":"2025-09-29T21:12:31.102523Z","published":"2022-01-06T20:30:46Z","severity":[{"type":"CVSS_V3","score":"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L"}],"affected":[{"package":{"name":"lodash","ecosystem":"npm"},"ranges":[]},{"package":{"name":"lodash","ecosystem":"RubyGems"},"ranges":[]}]}),
        );
        assert_eq!(d.unwrap().unwrap().severity, Severity::Medium);
    }
}
