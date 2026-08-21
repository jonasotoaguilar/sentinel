//! XDG OSV cache — schema v1, 24h TTL, atomic writes.
#![allow(dead_code)]
#![allow(clippy::possible_missing_else)]
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};
const TTL: Duration = Duration::from_secs(24 * 3600);
const SCHEMA: &str = "v1";
#[derive(Debug, Clone)]
pub struct XdgCache {
    base: Option<PathBuf>,
    now: fn() -> SystemTime,
}
impl XdgCache {
    pub fn new() -> Option<Self> {
        let p = directories::ProjectDirs::from("", "", "sentinel")?;
        Some(Self {
            base: Some(p.cache_dir().to_path_buf()),
            now: SystemTime::now,
        })
    }
    pub fn with_root(b: PathBuf) -> Self {
        Self {
            base: Some(b),
            now: SystemTime::now,
        }
    }
    pub fn with_root_and_clock(b: PathBuf, n: fn() -> SystemTime) -> Self {
        Self {
            base: Some(b),
            now: n,
        }
    }
    pub fn with_base_opt(b: Option<PathBuf>, n: fn() -> SystemTime) -> Self {
        Self { base: b, now: n }
    }
    pub fn get(&self, e: &str, n: &str, v: &str) -> Option<Vec<u8>> {
        self.get_inner(e, n, v, false)
    }
    pub fn get_offline(&self, e: &str, n: &str, v: &str) -> Option<Vec<u8>> {
        self.get_inner(e, n, v, true)
    }
    pub fn put(&self, e: &str, n: &str, v: &str, d: &[u8]) -> std::io::Result<bool> {
        let Some(base) = self.base.as_ref() else {
            return Ok(false);
        };
        if !Self::is_valid_eco(e) || !Self::is_valid_name(n, e) || !Self::is_valid_ver(v) {
            return Ok(false);
        }
        let Some(path) = self.cache_path(base, e, n, v) else {
            return Ok(false);
        };
        if !path.starts_with(base) || is_symlink(&path) || has_symlink_ancestor(base, &path) {
            return Ok(false);
        }
        if path.parent().is_some_and(|p| p.exists()) && !canon_contained(base, &path) {
            return Ok(false);
        }
        if serde_json::from_slice::<serde_json::Value>(d).is_err() {
            return Ok(false);
        }
        if let Some(p) = path.parent() {
            if has_symlink_ancestor(base, &path) {
                return Ok(false);
            }
            std::fs::create_dir_all(p)?;
            if !canon_contained(base, &path) {
                return Ok(false);
            }
        }
        let tmp = path
            .parent()
            .unwrap()
            .join(format!(".tmp-{}-{}", std::process::id(), {
                use std::sync::atomic::{AtomicU64, Ordering};
                static CTR: AtomicU64 = AtomicU64::new(0);
                CTR.fetch_add(1, Ordering::SeqCst)
            }));
        if let Err(e) = std::fs::write(&tmp, d) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        Ok(true)
    }
    fn get_inner(&self, e: &str, n: &str, v: &str, off: bool) -> Option<Vec<u8>> {
        let base = self.base.as_ref()?;
        if !Self::is_valid_eco(e) || !Self::is_valid_name(n, e) || !Self::is_valid_ver(v) {
            return None;
        }
        let path = self.cache_path(base, e, n, v)?;
        if !path.starts_with(base) || is_symlink(&path) || has_symlink_ancestor(base, &path) {
            return None;
        }
        if path.parent().is_some_and(|p| p.exists()) && !canon_contained(base, &path) {
            return None;
        }
        let meta = std::fs::metadata(&path).ok()?;
        if std::fs::symlink_metadata(&path).is_ok_and(|m| m.file_type().is_symlink()) {
            return None;
        }
        let mtime = meta.modified().ok()?;
        let now = (self.now)();
        if !off && now.duration_since(mtime).map_or(true, |a| a > TTL) {
            return None;
        }
        let b = std::fs::read(&path).ok()?;
        if serde_json::from_slice::<serde_json::Value>(&b).is_err() {
            return None;
        }
        if b.len() > 1024 * 1024 {
            return None;
        }
        Some(b)
    }
    fn cache_path(&self, base: &Path, e: &str, n: &str, v: &str) -> Option<PathBuf> {
        let pn = percent_encoding::utf8_percent_encode(n, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        let pv = percent_encoding::utf8_percent_encode(v, percent_encoding::NON_ALPHANUMERIC)
            .to_string();
        let p = base
            .join("osv")
            .join(SCHEMA)
            .join(e)
            .join(pn)
            .join(format!("{pv}.json"));
        if !p.starts_with(base) {
            return None;
        }
        Some(p)
    }
    fn is_valid_eco(e: &str) -> bool {
        e == "npm" || e == "PyPI"
    }
    #[rustfmt::skip]
    fn is_valid_name(n: &str, eco: &str) -> bool { if n.is_empty()||n.len()>256||n.contains(['\0','\n','\r']){return false;} let l=n.to_ascii_lowercase(); if l=="nan"||l.contains("..")||l.contains("<script"){return false;} if n.contains(['<','>','\\']){return false;} if eco=="PyPI"&&n.contains('/') {return false;} if n.starts_with('/')||n.contains("//"){return false;} n!="."&&n!=".." }
    #[rustfmt::skip]
    fn is_valid_ver(v: &str) -> bool { if v.is_empty()||v.len()>256||v.contains(['\0','\n','\r']){return false;} let l=v.to_ascii_lowercase(); if l=="nan"||l.contains("..")||l.contains("<script"){return false;} if v.contains(['<','>','/','\\']){return false;} if v.contains(['*','^','~','!',' ',';','\'',',','\"']){return false;} true }
}
#[rustfmt::skip]
fn is_symlink(p: &Path) -> bool {
    std::fs::symlink_metadata(p).is_ok_and(|m| m.file_type().is_symlink())
}
#[rustfmt::skip]
fn has_symlink_ancestor(b: &Path, p: &Path) -> bool { let mut cur=p.parent(); while let Some(a)=cur { if a==b {break;} if is_symlink(a){return true;} cur=a.parent(); } false }
#[rustfmt::skip]
fn canon_contained(b: &Path, p: &Path) -> bool { let Some(par)=p.parent() else {return false;}; if !par.exists(){return true;} let (Ok(cb),Ok(cp))=(b.canonicalize(),par.canonicalize()) else {return false;}; cp.starts_with(cb) }
#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{Duration, SystemTime},
    };
    const F: u64 = 1_700_000_000;
    fn now() -> SystemTime {
        SystemTime::UNIX_EPOCH + Duration::from_secs(F)
    }
    fn mtime(p: &Path, t: SystemTime) {
        fs::File::open(p).unwrap().set_modified(t).unwrap();
    }
    fn json() -> Vec<u8> {
        br#"{"id":"GHSA-xxxx","summary":"t"}"#.to_vec()
    }
    #[test]
    fn ttl_fresh_stale_and_future() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root_and_clock(d.path().to_path_buf(), now);
        c.put("npm", "lodash", "4.17.20", &json()).unwrap();
        let p = c.cache_path(d.path(), "npm", "lodash", "4.17.20").unwrap();
        mtime(&p, now() - Duration::from_secs(3600));
        assert!(c.get("npm", "lodash", "4.17.20").is_some());
        mtime(
            &p,
            SystemTime::UNIX_EPOCH + Duration::from_secs(F - 26 * 3600),
        );
        assert!(c.get("npm", "lodash", "4.17.20").is_none());
        assert!(p.exists());
        assert!(c.get_offline("npm", "lodash", "4.17.20").is_some());
        mtime(&p, SystemTime::UNIX_EPOCH + Duration::from_secs(F + 3600));
        assert!(
            c.get("npm", "lodash", "4.17.20").is_none(),
            "future miss online"
        );
        assert!(c.get_offline("npm", "lodash", "4.17.20").is_some());
        assert!(p.exists());
    }
    #[test]
    fn corrupt_large_and_schema_miss_without_rewrite() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root_and_clock(d.path().to_path_buf(), now);
        let p = c.cache_path(d.path(), "npm", "lodash", "4.17.20").unwrap();
        fs::create_dir_all(p.parent().unwrap()).unwrap();
        fs::write(&p, b"{ not json").unwrap();
        mtime(&p, now());
        assert!(c.get("npm", "lodash", "4.17.20").is_none());
        assert!(p.exists());
        assert_eq!(fs::read(&p).unwrap(), b"{ not json");
        let large = format!(r#"{{"id":"GHSA-xxxx","x":"{}"}}"#, "a".repeat(1024 * 1024));
        assert!(large.len() > 1024 * 1024);
        let lp = c.cache_path(d.path(), "npm", "large-pkg", "1.0.0").unwrap();
        fs::create_dir_all(lp.parent().unwrap()).unwrap();
        fs::write(&lp, large.as_bytes()).unwrap();
        mtime(&lp, now());
        assert!(c.get("npm", "large-pkg", "1.0.0").is_none());
        assert!(c.get_offline("npm", "large-pkg", "1.0.0").is_none());
        assert!(lp.exists());
        assert_eq!(fs::read(&lp).unwrap().len(), large.len());
        let d2 = tempfile::tempdir().unwrap();
        let c2 = XdgCache::with_root_and_clock(d2.path().to_path_buf(), now);
        let w = d2
            .path()
            .join("osv")
            .join("v0")
            .join("npm")
            .join("lodash")
            .join("4%2E17%2E20.json");
        fs::create_dir_all(w.parent().unwrap()).unwrap();
        fs::write(&w, json()).unwrap();
        let v1 = c2
            .cache_path(d2.path(), "npm", "lodash", "4.17.20")
            .unwrap();
        assert!(!v1.exists());
        assert!(c2.get("npm", "lodash", "4.17.20").is_none());
        assert!(w.exists());
    }
    #[test]
    fn traversal_and_percent_encoding() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root_and_clock(d.path().to_path_buf(), now);
        let cases = [
            ("npm", "../escape", "1.0.0"),
            ("npm", "../../etc/passwd", "1.0.0"),
            ("npm", "<script>alert(1)</script>", "1.0.0"),
            ("npm", "nan", "1.0.0"),
            ("npm", "lodash", "../1.0.0"),
            ("npm", "lodash", "1.0/../2.0"),
            ("npm", "lodash", "<script>"),
            ("PyPI", "a/b", "1.0.0"),
            ("npm", "lodash", "1.0.0/../../etc"),
            ("rubygems", "lodash", "1.0.0"),
        ];
        for (eco, n, v) in cases {
            assert!(c.get(eco, n, v).is_none(), "get {eco}/{n}/{v}");
            assert!(c.get_offline(eco, n, v).is_none());
            assert!(!c.put(eco, n, v, &json()).unwrap(), "put {eco}/{n}/{v}");
        }
        assert!(c.put("npm", "@babel/core", "7.0.0", &json()).unwrap());
        let p = c
            .cache_path(d.path(), "npm", "@babel/core", "7.0.0")
            .unwrap();
        mtime(&p, now());
        assert!(c.get("npm", "@babel/core", "7.0.0").is_some());
        assert!(p.starts_with(d.path()));
        assert!(p.to_string_lossy().contains("%40babel%2Fcore"));
        assert!(p.to_string_lossy().contains("7%2E0%2E0.json"));
        assert!(p.exists());
        assert!(!fs::read_dir(p.parent().unwrap()).unwrap().any(|e| {
            e.unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with(".tmp-")
        }));
    }
    #[test]
    fn project_dirs_none_is_skip() {
        let c = XdgCache::with_base_opt(None, now);
        assert!(c.get("npm", "lodash", "4.17.20").is_none());
        assert!(c.get_offline("npm", "lodash", "4.17.20").is_none());
        assert!(!c.put("npm", "lodash", "4.17.20", &json()).unwrap());
    }
    #[test]
    fn atomic_write_last_writer_wins() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root_and_clock(d.path().to_path_buf(), now);
        let v1 = br#"{"id":"GHSA-1111"}"#.to_vec();
        let v2 = br#"{"id":"GHSA-2222"}"#.to_vec();
        c.put("PyPI", "flask", "2.3.3", &v1).unwrap();
        c.put("PyPI", "flask", "2.3.3", &v2).unwrap();
        let p = c.cache_path(d.path(), "PyPI", "flask", "2.3.3").unwrap();
        mtime(&p, now());
        assert_eq!(c.get("PyPI", "flask", "2.3.3").unwrap(), v2);
    }
    #[cfg(unix)]
    #[test]
    fn symlink_escape_is_miss_and_put_skips() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root_and_clock(d.path().to_path_buf(), now);
        c.put("npm", "lodash", "4.17.20", &json()).unwrap();
        let p = c.cache_path(d.path(), "npm", "lodash", "4.17.20").unwrap();
        let outside = tempfile::tempdir().unwrap();
        let outside_file = outside.path().join("evil.json");
        fs::write(&outside_file, json()).unwrap();
        fs::remove_file(&p).unwrap();
        symlink(&outside_file, &p).unwrap();
        assert!(is_symlink(&p));
        assert!(c.get("npm", "lodash", "4.17.20").is_none());
        assert!(c.get_offline("npm", "lodash", "4.17.20").is_none());
        let d2 = tempfile::tempdir().unwrap();
        let c2 = XdgCache::with_root_and_clock(d2.path().to_path_buf(), now);
        let v1dir = d2.path().join("osv").join("v1");
        fs::create_dir_all(&v1dir).unwrap();
        symlink(outside.path(), v1dir.join("npm")).unwrap();
        assert!(!c2.put("npm", "lodash", "4.17.20", &json()).unwrap());
        assert!(!outside.path().join("lodash").exists());
        fs::create_dir_all(outside.path().join("lodash")).unwrap();
        fs::write(
            outside.path().join("lodash").join("4%2E17%2E20.json"),
            json(),
        )
        .unwrap();
        assert!(c2.get("npm", "lodash", "4.17.20").is_none());
        assert!(c2.get_offline("npm", "lodash", "4.17.20").is_none());
    }
}
