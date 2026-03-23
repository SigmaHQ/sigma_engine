//! Integration test that clones the SigmaHQ rule repository and attempts to
//! parse every rule found under the `rules/` and `rules-*` directories.
//!
//! The test is marked `#[ignore]` because it requires network access and takes
//! a while to run. Execute it explicitly with:
//!
//! ```sh
//! cargo test --test sigma_rule_parsing -- --ignored --nocapture
//! ```

use sigma_engine::SigmaCollection;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Recursively collect all `.yml` / `.yaml` files under `dir`.
fn collect_yaml_files(dir: &Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if !dir.is_dir() {
        return files;
    }
    for entry in fs::read_dir(dir).expect("failed to read directory") {
        let entry = entry.expect("failed to read directory entry");
        let path = entry.path();
        if path.is_dir() {
            files.extend(collect_yaml_files(&path));
        } else if let Some(ext) = path.extension() {
            if ext == "yml" || ext == "yaml" {
                files.push(path);
            }
        }
    }
    files
}

#[test]
#[ignore]
fn parse_sigma_rule_repository() {
    // ── 1. Clone the SigmaHQ rule repository into a temporary directory ──
    let tmp_dir = tempfile::tempdir().expect("failed to create temporary directory");
    let repo_dir = tmp_dir.path().join("sigma");

    let status = Command::new("git")
        .args([
            "clone",
            "--depth=1",
            "https://github.com/SigmaHQ/sigma.git",
            repo_dir.to_str().unwrap(),
        ])
        .status()
        .expect("failed to execute git clone");
    assert!(status.success(), "git clone failed");

    // ── 2. Discover rule directories (rules/ and rules-*) ───────────────
    let entries: Vec<PathBuf> = fs::read_dir(&repo_dir)
        .expect("failed to read repo directory")
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| {
            p.is_dir()
                && p.file_name()
                    .and_then(|n| n.to_str())
                    .map(|n| n == "rules" || n.starts_with("rules-"))
                    .unwrap_or(false)
        })
        .collect();

    assert!(
        !entries.is_empty(),
        "No rules/ or rules-* directories found in the cloned repository"
    );

    // ── 3. Collect all YAML rule files ──────────────────────────────────
    let mut yaml_files: Vec<PathBuf> = Vec::new();
    for dir in &entries {
        yaml_files.extend(collect_yaml_files(dir));
    }

    assert!(
        !yaml_files.is_empty(),
        "No YAML files found in rule directories"
    );

    // ── 4. Try to parse every file and collect results ──────────────────
    let mut success = 0usize;
    let mut failed = 0usize;
    let mut failures: Vec<(PathBuf, String)> = Vec::new();

    for path in &yaml_files {
        let content = fs::read_to_string(path).expect("failed to read YAML file");
        match SigmaCollection::from_yaml(&content) {
            Ok(_) => success += 1,
            Err(e) => {
                failed += 1;
                failures.push((path.clone(), e.to_string()));
            }
        }
    }

    // ── 5. Report ───────────────────────────────────────────────────────
    let total = yaml_files.len();
    println!("\n═══ Sigma Rule Repository Parsing Results ═══");
    println!("Total YAML files : {total}");
    println!("Parsed OK        : {success}");
    println!("Failed           : {failed}");
    println!(
        "Success rate     : {:.1}%",
        success as f64 / total as f64 * 100.0
    );

    if !failures.is_empty() {
        println!("\n── Failures ──");
        for (path, err) in &failures {
            println!("  {} → {}", path.display(), err);
        }
    }
    println!();
}
