//! Man page drift test (product P3, T5/S5).
//!
//! The pages under `man/man1` are rendered from the same clap command
//! definitions the binary uses, so a page cannot describe a flag the CLI
//! does not have. Rendering happens here, in tests, so no new subcommand
//! ships and no runtime dependency is added (`clap_mangen` is dev-only).
//!
//! Refresh the committed pages after any CLI change with:
//! `cargo test --test man_pages -- --ignored`

use std::fs;
use std::path::{Path, PathBuf};

use clap::CommandFactory;

// The binary's own command definitions, included by path, so a flag added
// to `src/cli.rs` reaches the generated pages with no second definition to
// keep in sync. That file references only the `Severity` type (and its four
// variants, in `FailUnder::threshold`) from the binary's finding model, so
// this module stands in just that type: man-page rendering never touches
// severities, and the mapping test below pins the documented correspondence
// between `--fail-under` levels and thresholds against the real code.
mod finding {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
    pub enum Severity {
        Low,
        Medium,
        High,
        Critical,
    }
}

#[path = "../src/cli.rs"]
mod cli;

/// The committed page directory: `man/man1` at the workspace root.
fn committed_dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("man")
        .join("man1")
}

/// Every page as `(filename, command)`: the top page plus one per
/// subcommand, recursing so a new subcommand appears automatically and a
/// removed one leaves a stale file the drift test reports.
fn pages() -> Vec<(String, clap::Command)> {
    let mut top = cli::Cli::command();
    top.build();
    let mut out = Vec::new();
    let root = top.clone().bin_name("sentinel");
    out.push(("sentinel.1".to_string(), root));
    collect(&top, "sentinel".to_string(), &mut out);
    out
}

/// Recursively collects one page per subcommand under `prefix`, naming
/// files and titles with dashes (`sentinel-cache-prune.1`). The synthetic
/// `help` subcommands clap adds are skipped: they carry no options of
/// their own and a page per `help <target>` would be noise.
fn collect(prefix_cmd: &clap::Command, prefix: String, out: &mut Vec<(String, clap::Command)>) {
    for sub in prefix_cmd
        .get_subcommands()
        .filter(|sub| sub.get_name() != "help")
    {
        let page = format!("{}-{}", prefix, sub.get_name());
        let owned = sub.clone().bin_name(page.clone());
        out.push((format!("{page}.1"), owned));
        collect(sub, page, out);
    }
}

/// Renders every page into `dir`, creating it when missing.
fn generate_into(dir: &Path) {
    fs::create_dir_all(dir).unwrap();
    for (filename, cmd) in pages() {
        let man = clap_mangen::Man::new(cmd);
        let mut rendered: Vec<u8> = Vec::new();
        man.render(&mut rendered).unwrap();
        fs::write(dir.join(&filename), rendered).unwrap();
    }
}

/// Sorted `*.1` filenames present in `dir`; missing dir means no pages.
fn committed_names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".1"))
        .collect();
    names.sort();
    names
}

#[test]
fn committed_man_pages_match_generated_output() {
    let committed = committed_dir();
    assert!(
        committed.is_dir(),
        "man pages missing: {committed:?} does not exist; regenerate with \
         `cargo test --test man_pages -- --ignored`"
    );
    let scratch = tempfile::tempdir().unwrap();
    generate_into(scratch.path());

    let mut generated: Vec<String> = fs::read_dir(scratch.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    generated.sort();
    let kept = committed_names(&committed);
    assert_eq!(
        kept, generated,
        "man page set drifted (committed {kept:?}, generated {generated:?}); regenerate with \
         `cargo test --test man_pages -- --ignored`"
    );

    for name in &generated {
        let fresh = fs::read(scratch.path().join(name)).unwrap();
        let kept_bytes = fs::read(committed.join(name)).unwrap();
        assert!(
            fresh == kept_bytes,
            "man page drifted: {name}; regenerate with \
             `cargo test --test man_pages -- --ignored`"
        );
    }
}

/// The exit policy the `sentinel-scan` page documents, pinned against the
/// real mapping: each `--fail-under` level resolves to its severity
/// threshold, `none` is report-only, and absence means `low`.
#[test]
fn fail_under_threshold_mapping_matches_documented_policy() {
    use cli::FailUnder;
    use finding::Severity;

    assert_eq!(FailUnder::Critical.threshold(), Some(Severity::Critical));
    assert_eq!(FailUnder::High.threshold(), Some(Severity::High));
    assert_eq!(FailUnder::Medium.threshold(), Some(Severity::Medium));
    assert_eq!(FailUnder::Low.threshold(), Some(Severity::Low));
    assert_eq!(FailUnder::None.threshold(), None);
    assert_eq!(FailUnder::default(), FailUnder::Low);
}

/// Regenerates the committed pages (ignored by default so a normal
/// `cargo test` run never rewrites the tree). Run explicitly after any
/// CLI change:
/// `cargo test --test man_pages -- --ignored`
#[test]
#[ignore]
fn regenerate_committed_man_pages() {
    let dir = committed_dir();
    generate_into(&dir);
    let mut generated: Vec<String> = fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|name| name.ends_with(".1"))
        .collect();
    generated.sort();
    let expected: Vec<String> = pages().into_iter().map(|(name, _)| name).collect();
    for stale in generated.iter().filter(|name| !expected.contains(name)) {
        fs::remove_file(dir.join(stale)).unwrap();
    }
}
