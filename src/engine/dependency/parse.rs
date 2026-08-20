//! Pinned manifest ingestion.
#![allow(dead_code)]
use crate::{discovery::MAX_SCAN_FILE_BYTES, finding::Diagnostic};
use serde_json::Value as J;
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Ecosystem {
    Npm,
    PyPI,
}
impl Ecosystem {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Npm => "npm",
            Self::PyPI => "PyPI",
        }
    }
}
impl std::fmt::Display for Ecosystem {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pin {
    pub ecosystem: Ecosystem,
    pub name: String,
    pub version: String,
    pub path: String,
    pub line: u64,
    pub column: u64,
}
fn d(p: &str, c: &'static str, m: String) -> Diagnostic {
    Diagnostic {
        code: c,
        path: p.into(),
        rule: String::new(),
        message: m,
    }
}
pub fn parse_file(p: &str, b: &[u8]) -> (Vec<Pin>, Vec<Diagnostic>) {
    let q = p.replace('\\', "/");
    if b.len() as u64 >= MAX_SCAN_FILE_BYTES {
        return (
            Vec::new(),
            vec![d(
                &q,
                "skipped-large",
                format!("{} bytes exceeds the 10 MiB scan limit", b.len()),
            )],
        );
    }
    if q.ends_with("package-lock.json") {
        parse_lock(&q, b)
    } else if q.ends_with("requirements.txt") {
        parse_req(&q, b)
    } else {
        (Vec::new(), Vec::new())
    }
}
fn parse_lock(p: &str, b: &[u8]) -> (Vec<Pin>, Vec<Diagnostic>) {
    let v: J = match serde_json::from_slice(b) {
        Ok(v) => v,
        Err(e) => {
            return (
                Vec::new(),
                vec![d(p, "manifest-parse-failed", san(&e.to_string()))],
            );
        }
    };
    let mut pins = Vec::new();
    let mut ds = Vec::new();
    if let Some(o) = v.get("dependencies").and_then(|x| x.as_object()) {
        for (n, e) in o {
            handle_npm(p, n, e, &mut pins, &mut ds);
        }
    }
    if let Some(o) = v.get("packages").and_then(|x| x.as_object()) {
        for (k, e) in o {
            if k.is_empty() {
                continue;
            }
            let Some(n) = npm_name(k) else {
                continue;
            };
            handle_npm(p, &n, e, &mut pins, &mut ds);
        }
    }
    pins.sort();
    pins.dedup();
    ds.sort();
    (pins, ds)
}
fn handle_npm(p: &str, name: &str, entry: &J, pins: &mut Vec<Pin>, ds: &mut Vec<Diagnostic>) {
    if !safe_name(name, Ecosystem::Npm) {
        ds.push(d(
            p,
            "manifest-parse-failed",
            format!("invalid package name at {p}:1"),
        ));
        return;
    }
    match entry.get("version").and_then(|x| x.as_str()) {
        Some(v) if safe_ver(v) && !v.is_empty() => pins.push(Pin {
            ecosystem: Ecosystem::Npm,
            name: name.into(),
            version: v.into(),
            path: p.into(),
            line: 1,
            column: 1,
        }),
        Some(_) => ds.push(d(
            p,
            "version-unpinned-skipped",
            format!("unpinned or invalid version at {p}:1"),
        )),
        None => ds.push(d(
            p,
            "version-unpinned-skipped",
            format!("missing version at {p}:1"),
        )),
    }
}
fn npm_name(k: &str) -> Option<String> {
    let r = k
        .rfind("node_modules/")
        .map(|i| &k[i + "node_modules/".len()..])
        .unwrap_or(k);
    if r.is_empty() {
        return None;
    }
    if r.starts_with('@') {
        let mut s = r.splitn(3, '/');
        let a = s.next()?;
        let b = s.next()?;
        if a.is_empty() || b.is_empty() {
            None
        } else {
            Some(format!("{a}/{b}"))
        }
    } else {
        let n = r.split('/').next()?;
        if n.is_empty() { None } else { Some(n.into()) }
    }
}
fn parse_req(p: &str, b: &[u8]) -> (Vec<Pin>, Vec<Diagnostic>) {
    let t = String::from_utf8_lossy(b);
    let mut pins = Vec::new();
    let mut ds = Vec::new();
    for (i, raw) in t.lines().enumerate() {
        let ln = i as u64 + 1;
        let q = raw.trim();
        if q.is_empty() || q.starts_with('#') {
            continue;
        }
        let cur = q.find('#').map(|x| q[..x].trim()).unwrap_or(q);
        if cur.is_empty() {
            continue;
        }
        let sp: Vec<&str> = cur.split("==").collect();
        if sp.len() != 2 || cur.starts_with('-') {
            ds.push(d(
                p,
                "version-unpinned-skipped",
                format!("unpinned or range at {p}:{ln}"),
            ));
            continue;
        }
        let n = sp[0].trim();
        let v = sp[1].trim();
        if n.contains('[')
            || n.contains(']')
            || v.contains(';')
            || v.contains(' ')
            || n.is_empty()
            || v.is_empty()
            || !safe_name(n, Ecosystem::PyPI)
            || !safe_ver(v)
        {
            let code = if !safe_name(n, Ecosystem::PyPI) || !safe_ver(v) {
                "manifest-parse-failed"
            } else {
                "version-unpinned-skipped"
            };
            ds.push(d(p, code, format!("invalid or unpinned at {p}:{ln}")));
            continue;
        }
        pins.push(Pin {
            ecosystem: Ecosystem::PyPI,
            name: n.into(),
            version: v.into(),
            path: p.into(),
            line: ln,
            column: 1,
        });
    }
    pins.sort();
    pins.dedup();
    ds.sort();
    (pins, ds)
}
fn safe_name(n: &str, e: Ecosystem) -> bool {
    if n.is_empty() || n.len() > 256 || n.contains(['\0', '\n', '\r']) {
        return false;
    }
    let l = n.to_ascii_lowercase();
    if l.contains("..") || l.contains("<script") || n.contains(['<', '>', '\\']) {
        return false;
    }
    if e == Ecosystem::PyPI && n.contains('/') {
        return false;
    }
    l != "nan"
}
fn safe_ver(v: &str) -> bool {
    if v.is_empty() || v.len() > 256 || v.contains(['\0', '\n', '\r']) {
        return false;
    }
    let l = v.to_ascii_lowercase();
    if l == "nan" || l.contains("<script") || v.contains(['<', '>', '/', '\\']) || v.contains("..")
    {
        return false;
    }
    !v.contains(['*', '^', '~', '!', ' ', ';', ','])
}
fn san(m: &str) -> String {
    m.chars().filter(|c| !c.is_control()).take(200).collect()
}
#[cfg(test)]
mod tests {
    use super::*;
    fn no_leak(ds: &[Diagnostic], r: &str) {
        for d in ds {
            assert!(!d.message.contains(r));
        }
    }
    #[test]
    fn all() {
        let (p, _ds) = parse_file(
            "requirements.txt",
            b"requests>=2.0\nflask==2.3.3\ninvalid\n",
        );
        assert_eq!(p.len(), 1);
        assert_eq!(p[0].name, "flask");
        let b = format!(
            "{}==1.0\n{}==1.0\n(pkg==nan\n",
            "<script>alert(1)</script>", "../etc/passwd"
        )
        .into_bytes();
        let (p, ds) = parse_file("requirements.txt", &b);
        assert!(p.is_empty());
        no_leak(&ds, "<script>");
        let (p, ds) = parse_file(
            "a/requirements.txt",
            b"flask==2.3.3\nrequests[security]==2.28.0\n",
        );
        assert_eq!(p.len(), 1);
        assert_eq!(ds.len(), 1);
        let big = vec![b'a'; MAX_SCAN_FILE_BYTES as usize];
        let (_p, ds) = parse_file("requirements.txt", &big);
        assert_eq!(ds[0].code, "skipped-large");
        let (p, ds) = parse_file("pyproject.toml", b"[tool]");
        assert!(p.is_empty() && ds.is_empty());
        let (p, ds) = parse_file("package-lock.json", b"{ invalid");
        assert!(p.is_empty());
        assert_eq!(ds[0].code, "manifest-parse-failed");
        let j = r#"{"packages":{"node_modules/<script>":{"version":"1.0.0"},"node_modules/../escape":{"version":"1.0.0"}}}"#;
        let (p, ds) = parse_file("package-lock.json", j.as_bytes());
        assert!(p.is_empty());
        no_leak(&ds, "<script>");
        let (p, _) = parse_file(
            "package-lock.json",
            r#"{"dependencies":{"lodash":{"version":"4.17.20"}}}"#.as_bytes(),
        );
        assert!(p.iter().any(|x| x.name == "lodash"));
        let (p, _) = parse_file("package-lock.json", r#"{"lockfileVersion":2,"packages":{"":{"name":"t"},"node_modules/lodash":{"version":"4.17.20"}}}"#.as_bytes());
        assert_eq!(p.len(), 1);
    }
}
