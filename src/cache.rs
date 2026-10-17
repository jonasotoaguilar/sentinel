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
    /// The resolved cache location, if the system yields one. `cache path`
    /// prints exactly this; destructive commands resolve through
    /// [`Self::validated_root`] instead of trusting it blindly.
    pub fn location(&self) -> Option<PathBuf> {
        self.base.clone()
    }
    /// The deletion root: a base that is present, non-empty, absolute, and
    /// not the filesystem root. Every destructive command runs through
    /// this check first, so a wrong resolution refuses with a clear error
    /// instead of deleting something it cannot prove is the cache.
    pub fn validated_root(&self) -> Result<PathBuf, CacheError> {
        let Some(base) = self.base.as_ref() else {
            return Err(CacheError::Unavailable);
        };
        if base.as_os_str().is_empty() {
            return Err(CacheError::Empty);
        }
        if !base.is_absolute() {
            return Err(CacheError::NotAbsolute(base.clone()));
        }
        if base.parent().is_none() {
            return Err(CacheError::Root);
        }
        Ok(base.clone())
    }
    /// Refuses any deletion candidate that is not provably inside `root`:
    /// a lexical prefix check first (catches `..` escapes without touching
    /// the filesystem), then the canonical check for pre-existing parents
    /// (catches symlinked ancestors) — the same two guards the read and
    /// write paths above already enforce per entry.
    pub(crate) fn ensure_contained(root: &Path, candidate: &Path) -> Result<(), CacheError> {
        // The root contains itself: the canonical-parent check below only
        // makes sense for entries *under* the root, whose parent must stay
        // inside it.
        if candidate == root {
            return Ok(());
        }
        if !candidate.starts_with(root) {
            return Err(CacheError::Outside(candidate.to_path_buf()));
        }
        if candidate.parent().is_some_and(|p| p.exists()) && !canon_contained(root, candidate) {
            return Err(CacheError::Outside(candidate.to_path_buf()));
        }
        Ok(())
    }
    /// Empties the cache directory, reporting the removed entry count and
    /// reclaimed bytes. Clearing a missing or empty cache succeeds with
    /// zero. The root itself is never removed; symlinks are unlinked,
    /// never followed; anything outside the root refuses instead of deleting.
    pub fn clear(&self) -> Result<CacheStats, CacheError> {
        let root = self.validated_root()?;
        if !root.exists() {
            return Ok(CacheStats::zero());
        }
        // Resolve symlinks in the root itself: a root aliasing `/` must
        // still refuse, and canonicalization can only narrow containment.
        let canon = root
            .canonicalize()
            .map_err(|e| CacheError::Io(e.to_string()))?;
        if canon.parent().is_none() {
            return Err(CacheError::Root);
        }
        let mut stats = CacheStats::zero();
        Self::remove_tree(&canon, &canon, &mut stats)?;
        Ok(stats)
    }
    /// Deletes `path` (file, link, or directory) after proving it sits
    /// inside `root`. Directories are emptied first and removed unless they
    /// *are* the root; symlinks are unlinked without descending, so a link
    /// pointing outside the cache can never pull its target into the delete.
    fn remove_tree(path: &Path, root: &Path, stats: &mut CacheStats) -> Result<(), CacheError> {
        Self::ensure_contained(root, path)?;
        let meta = std::fs::symlink_metadata(path).map_err(|e| CacheError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            std::fs::remove_file(path).map_err(|e| CacheError::Io(e.to_string()))?;
            stats.entries += 1;
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| CacheError::Io(e.to_string()))? {
                let child = entry.map_err(|e| CacheError::Io(e.to_string()))?.path();
                Self::remove_tree(&child, root, stats)?;
            }
            if path != root {
                std::fs::remove_dir(path).map_err(|e| CacheError::Io(e.to_string()))?;
            }
            return Ok(());
        }
        stats.entries += 1;
        stats.bytes += meta.len();
        std::fs::remove_file(path).map_err(|e| CacheError::Io(e.to_string()))?;
        Ok(())
    }
    /// Removes entries not used since `older_than` ago — last use
    /// approximated by modification time, since access times are unreliable
    /// — and reports what was removed. Directories left empty are removed;
    /// the root itself and fresh entries stay. A prune with nothing to
    /// remove succeeds with zero.
    pub fn prune(&self, older_than: Duration) -> Result<CacheStats, CacheError> {
        let root = self.validated_root()?;
        if !root.exists() {
            return Ok(CacheStats::zero());
        }
        let canon = root
            .canonicalize()
            .map_err(|e| CacheError::Io(e.to_string()))?;
        if canon.parent().is_none() {
            return Err(CacheError::Root);
        }
        let mut stats = CacheStats::zero();
        Self::prune_tree(&canon, &canon, older_than, (self.now)(), &mut stats)?;
        Ok(stats)
    }
    /// The prune half of [`Self::remove_tree`]: stale files and links are
    /// deleted, fresh ones kept, and directories removed only when left
    /// empty (never the root). Future mtimes and unreadable clocks keep
    /// their entries — a prune deletes only proven-stale data.
    fn prune_tree(
        path: &Path,
        root: &Path,
        older_than: Duration,
        now: SystemTime,
        stats: &mut CacheStats,
    ) -> Result<(), CacheError> {
        Self::ensure_contained(root, path)?;
        let meta = std::fs::symlink_metadata(path).map_err(|e| CacheError::Io(e.to_string()))?;
        if meta.file_type().is_symlink() {
            if is_stale(now, meta.modified().ok(), older_than) {
                std::fs::remove_file(path).map_err(|e| CacheError::Io(e.to_string()))?;
                stats.entries += 1;
            }
            return Ok(());
        }
        if meta.is_dir() {
            for entry in std::fs::read_dir(path).map_err(|e| CacheError::Io(e.to_string()))? {
                let child = entry.map_err(|e| CacheError::Io(e.to_string()))?.path();
                Self::prune_tree(&child, root, older_than, now, stats)?;
            }
            if path != root
                && std::fs::read_dir(path)
                    .map_err(|e| CacheError::Io(e.to_string()))?
                    .next()
                    .is_none()
            {
                std::fs::remove_dir(path).map_err(|e| CacheError::Io(e.to_string()))?;
            }
            return Ok(());
        }
        if is_stale(now, meta.modified().ok(), older_than) {
            stats.entries += 1;
            stats.bytes += meta.len();
            std::fs::remove_file(path).map_err(|e| CacheError::Io(e.to_string()))?;
        }
        Ok(())
    }
    pub fn get(&self, e: &str, n: &str, v: &str) -> Option<Vec<u8>> {
        self.get_inner(e, n, v, false)
    }
    pub fn get_offline(&self, e: &str, n: &str, v: &str) -> Option<Vec<u8>> {
        self.get_inner(e, n, v, true)
    }
    #[rustfmt::skip]    pub(crate) fn entry_present(&self,e:&str,n:&str,v:&str)->bool{let Some(base)=self.base.as_ref()else{return false;};if !Self::is_valid_eco(e)||!Self::is_valid_name(n,e)||!Self::is_valid_ver(v){return false;}let Some(path)=self.cache_path(base,e,n,v)else{return false;};if !path.starts_with(base)||is_symlink(&path)||has_symlink_ancestor(base,&path){return false;}if path.parent().is_some_and(|p|p.exists())&&!canon_contained(base,&path){return false;}std::fs::symlink_metadata(&path).is_ok_and(|m|m.file_type().is_file())}
    #[rustfmt::skip]    pub(crate) fn entry_path(&self,e:&str,n:&str,v:&str)->Option<PathBuf>{let base=self.base.as_ref()?;self.cache_path(base,e,n,v)}
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
/// What a destructive cache command removed: the entry count and, where
/// cheap (regular-file sizes already in hand), the reclaimed bytes.
/// Symlinks count as entries with zero bytes — the link is unlinked, its
/// target never read, so there is no honest byte count to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStats {
    pub entries: u64,
    pub bytes: u64,
}
impl CacheStats {
    fn zero() -> Self {
        Self {
            entries: 0,
            bytes: 0,
        }
    }
}
/// Why a destructive cache command refused to run. Every variant means
/// "the resolved location cannot be proven safe", so the caller reports
/// the reason instead of guessing which directory was meant.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CacheError {
    /// No base directory at all (e.g. no home directory on this system).
    Unavailable,
    /// The resolved location is empty.
    Empty,
    /// The resolved location is not absolute, so containment cannot hold.
    NotAbsolute(PathBuf),
    /// The resolved location is the filesystem root (or a symlinked alias
    /// of it): deleting inside it would delete the machine.
    Root,
    /// A deletion candidate escapes the resolved root.
    Outside(PathBuf),
    /// Filesystem I/O while deleting.
    Io(String),
}
impl std::fmt::Display for CacheError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Unavailable => write!(f, "no cache directory is available on this system"),
            Self::Empty => write!(f, "resolved cache location is empty"),
            Self::NotAbsolute(path) => {
                write!(
                    f,
                    "resolved cache location is not absolute: {}",
                    path.display()
                )
            }
            Self::Root => write!(f, "resolved cache location is the filesystem root"),
            Self::Outside(path) => write!(
                f,
                "refusing to delete outside the cache directory: {}",
                path.display()
            ),
            Self::Io(error) => write!(f, "{error}"),
        }
    }
}
impl std::error::Error for CacheError {}
/// Stale means provably older than the threshold; future mtimes and
/// unreadable clocks keep their entries.
fn is_stale(now: SystemTime, mtime: Option<SystemTime>, older_than: Duration) -> bool {
    match mtime.and_then(|t| now.duration_since(t).ok()) {
        Some(age) => age >= older_than,
        None => false,
    }
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
    #[test]
    fn clear_removes_entries_and_reports_counts() {
        use std::time::Duration;
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root(d.path().to_path_buf());
        c.put("npm", "lodash", "4.17.20", &json()).unwrap();
        c.put("PyPI", "flask", "2.3.3", &json()).unwrap();
        let stats = c.clear().unwrap();
        assert_eq!(stats.entries, 2, "one entry per cached pin");
        assert_eq!(
            stats.bytes,
            2 * json().len() as u64,
            "bytes are the reclaimed entry bytes"
        );
        assert!(
            d.path().exists(),
            "clear empties the root, never removes it"
        );
        assert!(
            c.get_offline("npm", "lodash", "4.17.20").is_none(),
            "cleared entries stay cleared"
        );
        assert!(
            !walk_json_files(d.path()).next().is_some(),
            "no entry file survives a clear"
        );
        let _ = Duration::from_secs(0);
    }
    #[test]
    fn clear_empty_cache_succeeds_with_zero() {
        let d = tempfile::tempdir().unwrap();
        // Missing root: nothing to remove is a success, not an error.
        let missing = XdgCache::with_root(d.path().join("not-yet-created"));
        let stats = missing.clear().unwrap();
        assert_eq!((stats.entries, stats.bytes), (0, 0));
        // Existing but empty root: same success.
        let empty = XdgCache::with_root(d.path().to_path_buf());
        let stats = empty.clear().unwrap();
        assert_eq!((stats.entries, stats.bytes), (0, 0));
        assert!(d.path().exists());
    }
    #[test]
    fn prune_removes_only_old_entries() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root(d.path().to_path_buf());
        c.put("npm", "stale-pkg", "1.0.0", &json()).unwrap();
        c.put("npm", "fresh-pkg", "1.0.0", &json()).unwrap();
        let stale = c.cache_path(d.path(), "npm", "stale-pkg", "1.0.0").unwrap();
        let fresh = c.cache_path(d.path(), "npm", "fresh-pkg", "1.0.0").unwrap();
        mtime(&stale, SystemTime::now() - Duration::from_secs(40 * 86400));
        mtime(&fresh, SystemTime::now());
        let stats = c.prune(Duration::from_secs(30 * 86400)).unwrap();
        assert_eq!(stats.entries, 1, "only the stale entry is pruned");
        assert!(!stale.exists(), "stale entry removed");
        assert!(fresh.exists(), "fresh entry survives");
        assert!(
            c.get("npm", "fresh-pkg", "1.0.0").is_some(),
            "the surviving entry still reads"
        );
    }
    #[test]
    fn prune_keeps_recent_entries() {
        let d = tempfile::tempdir().unwrap();
        let c = XdgCache::with_root(d.path().to_path_buf());
        c.put("npm", "lodash", "4.17.20", &json()).unwrap();
        c.put("PyPI", "flask", "2.3.3", &json()).unwrap();
        let stats = c.prune(Duration::from_secs(30 * 86400)).unwrap();
        assert_eq!((stats.entries, stats.bytes), (0, 0));
        assert!(
            c.get("npm", "lodash", "4.17.20").is_some()
                && c.get("PyPI", "flask", "2.3.3").is_some(),
            "a prune with nothing to remove changes nothing"
        );
    }
    #[test]
    fn refuses_empty_and_root_locations() {
        for root in [PathBuf::from(""), PathBuf::from("/")] {
            let c = XdgCache::with_root(root);
            assert!(
                c.clear().is_err(),
                "clear refuses a location that cannot be contained"
            );
            assert!(
                c.prune(Duration::from_secs(30 * 86400)).is_err(),
                "prune refuses a location that cannot be contained"
            );
        }
    }
    #[test]
    fn containment_refuses_a_path_outside_the_cache() {
        let d = tempfile::tempdir().unwrap();
        let root = d.path().to_path_buf();
        assert!(
            XdgCache::ensure_contained(&root, &root.join("osv").join("v1").join("x.json")).is_ok(),
            "entries inside the root are deletable"
        );
        assert!(
            XdgCache::ensure_contained(&root, Path::new("/etc/passwd")).is_err(),
            "an absolute path outside the root is refused"
        );
        assert!(
            XdgCache::ensure_contained(&root, &root.join("..").join("escape.json")).is_err(),
            "a lexical escape through `..` is refused before any delete"
        );
    }
    #[cfg(unix)]
    #[test]
    fn clear_removes_the_link_never_its_target() {
        use std::os::unix::fs::symlink;
        let d = tempfile::tempdir().unwrap();
        let outside = tempfile::tempdir().unwrap();
        let target = outside.path().join("precious.json");
        fs::write(&target, json()).unwrap();
        let c = XdgCache::with_root(d.path().to_path_buf());
        c.put("npm", "lodash", "4.17.20", &json()).unwrap();
        let link = c
            .cache_path(d.path(), "npm", "linked-pkg", "9.9.9")
            .unwrap();
        fs::create_dir_all(link.parent().unwrap()).unwrap();
        symlink(&target, &link).unwrap();
        let stats = c.clear().unwrap();
        assert!(!link.exists() && fs::symlink_metadata(&link).is_err());
        assert_eq!(
            fs::read(&target).unwrap(),
            json(),
            "the target outside the cache is never followed, never deleted"
        );
        assert!(stats.entries >= 2, "the link counts as a removed entry");
    }
    fn walk_json_files(root: &Path) -> impl Iterator<Item = PathBuf> {
        let mut stack = vec![root.to_path_buf()];
        let mut out = Vec::new();
        while let Some(dir) = stack.pop() {
            let Ok(entries) = fs::read_dir(&dir) else {
                continue;
            };
            for entry in entries.flatten() {
                let path = entry.path();
                if path.is_dir() && !is_symlink(&path) {
                    stack.push(path);
                } else if path.extension().is_some_and(|e| e == "json") {
                    out.push(path);
                }
            }
        }
        out.into_iter()
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
