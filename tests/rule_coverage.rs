//! Integration tests that verify every rule in every TOML rules file fires on
//! at least one realistic hit snippet and does NOT fire on the corresponding
//! safe-alternative miss snippet.
//!
//! Fixture data lives in tests/fixtures/<rules-file-stem>.toml.
//! Each [[case]] entry has: rule, ext, hit, miss.
//!
//! Run with: cargo test --test rule_coverage

use serde::Deserialize;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};

// ── Fixture types ─────────────────────────────────────────────────────────────

#[derive(Deserialize)]
struct Fixture {
    rules_file: String,
    ext: String,
    #[serde(rename = "case")]
    cases: Vec<Case>,
}

#[derive(Deserialize)]
struct Case {
    rule: String,
    /// Override the fixture-level extension for this one case.
    ext: Option<String>,
    #[serde(default)]
    hit: String,
    /// Base64-encoded hit string — decoded at runtime so the fixture file doesn't contain
    /// raw secret patterns that trigger GitHub's secret scanner.
    hit_b64: Option<String>,
    /// Array of base64-encoded fragments decoded and concatenated — use when GitHub's
    /// scanner recognises the single hit_b64 value (it decodes base64 before scanning).
    hit_b64_parts: Option<Vec<String>>,
    #[serde(default)]
    miss: String,
    /// Base64-encoded miss string.
    miss_b64: Option<String>,
    miss_b64_parts: Option<Vec<String>>,
}

/// Minimal base64 decoder — avoids pulling in an external crate for test-only use.
fn b64_decode(s: &str) -> String {
    const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut lut = [0u8; 256];
    for (i, &c) in ALPHA.iter().enumerate() {
        lut[c as usize] = i as u8;
    }
    let bytes: Vec<u8> = s.bytes().filter(|&b| b != b'=').collect();
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4);
    for chunk in bytes.chunks(4) {
        let v: Vec<u8> = chunk.iter().map(|&b| lut[b as usize]).collect();
        out.push((v[0] << 2) | (v[1] >> 4));
        if v.len() > 2 { out.push((v[1] << 4) | (v[2] >> 2)); }
        if v.len() > 3 { out.push((v[2] << 6) | v[3]); }
    }
    String::from_utf8(out).expect("b64 decoded to valid UTF-8")
}

// ── Binary discovery ──────────────────────────────────────────────────────────

fn yarecs_bin() -> PathBuf {
    // Integration test exe lives at  target/debug/deps/<name>-<hash>[.exe]
    // The yarecs binary is at        target/debug/yarecs[.exe]
    let mut path = std::env::current_exe().expect("current_exe");
    path.pop(); // drop binary name
    if path.ends_with("deps") {
        path.pop(); // deps → debug
    }
    let mut bin = path.join("yarecs");
    if cfg!(windows) {
        bin.set_extension("exe");
    }
    assert!(
        bin.exists(),
        "yarecs binary not found at {bin:?} — run `cargo build` first"
    );
    bin
}

// ── Helpers ───────────────────────────────────────────────────────────────────

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn run_yarecs(bin: &Path, rules_file: &str, ext: &str, source: &str) -> String {
    let id  = COUNTER.fetch_add(1, Ordering::Relaxed);
    let tmp = std::env::temp_dir().join(format!("yarecs_case_{id}.{ext}"));
    fs::write(&tmp, source).expect("write temp file");
    let out = Command::new(bin)
        .arg("--config")
        .arg(rules_file)
        .arg("--extensions")
        .arg(ext)
        .arg("--format")
        .arg("json")
        .arg(&tmp)
        .output()
        .unwrap_or_else(|e| panic!("failed to spawn yarecs: {e}"));
    let _ = fs::remove_file(&tmp);
    String::from_utf8_lossy(&out.stdout).into_owned()
}

/// Returns true if the JSON output contains a match for `rule`.
fn rule_fires(json: &str, rule: &str) -> bool {
    // JSON format: {"rule":"rule_name",...}
    let needle = format!("\"rule\":{rule:?}");
    json.contains(&needle)
}

fn run_fixture(fixture_path: &str) {
    let content = fs::read_to_string(fixture_path)
        .unwrap_or_else(|e| panic!("cannot read fixture {fixture_path}: {e}"));
    let fixture: Fixture = toml::from_str(&content)
        .unwrap_or_else(|e| panic!("cannot parse fixture {fixture_path}: {e}"));

    let bin = yarecs_bin();
    let mut failures: Vec<String> = Vec::new();

    for c in &fixture.cases {
        let ext = c.ext.as_deref().unwrap_or(&fixture.ext);

        let hit_str = c.hit_b64_parts.as_ref()
            .map(|p| p.iter().map(|s| b64_decode(s)).collect::<String>())
            .or_else(|| c.hit_b64.as_deref().map(b64_decode))
            .unwrap_or_else(|| c.hit.clone());
        let miss_str = c.miss_b64_parts.as_ref()
            .map(|p| p.iter().map(|s| b64_decode(s)).collect::<String>())
            .or_else(|| c.miss_b64.as_deref().map(b64_decode))
            .unwrap_or_else(|| c.miss.clone());

        // Hit: the rule MUST fire.
        let hit_json = run_yarecs(&bin, &fixture.rules_file, ext, &hit_str);
        if !rule_fires(&hit_json, &c.rule) {
            failures.push(format!(
                "  HIT MISS  rule={:?}  ext={ext:?}\n    snippet: {:?}",
                c.rule,
                hit_str.trim(),
            ));
        }

        // Miss: the rule must NOT fire.
        let miss_json = run_yarecs(&bin, &fixture.rules_file, ext, &miss_str);
        if rule_fires(&miss_json, &c.rule) {
            failures.push(format!(
                "  FALSE POS rule={:?}  ext={ext:?}\n    snippet: {:?}",
                c.rule,
                miss_str.trim(),
            ));
        }
    }

    if !failures.is_empty() {
        panic!(
            "{} failure(s) in {fixture_path}:\n{}",
            failures.len(),
            failures.join("\n")
        );
    }
}

// ── One test per rules file ───────────────────────────────────────────────────

#[test]
fn c_cpp_security() {
    run_fixture("tests/fixtures/c_cpp_security.toml");
}

#[test]
fn csharp_security() {
    run_fixture("tests/fixtures/csharp_security.toml");
}

#[test]
fn generic_secrets() {
    run_fixture("tests/fixtures/generic_secrets.toml");
}

#[test]
fn go_security() {
    run_fixture("tests/fixtures/go_security.toml");
}

#[test]
fn java_security() {
    run_fixture("tests/fixtures/java_security.toml");
}

#[test]
fn kotlin_security() {
    run_fixture("tests/fixtures/kotlin_security.toml");
}

#[test]
fn rust_security() {
    run_fixture("tests/fixtures/rust_security.toml");
}

#[test]
fn unreal_engine5() {
    run_fixture("tests/fixtures/unreal_engine5.toml");
}

#[test]
fn generic_sql() {
    run_fixture("tests/fixtures/generic_sql.toml");
}

#[test]
fn generic_shell() {
    run_fixture("tests/fixtures/generic_shell.toml");
}

#[test]
fn python_security() {
    run_fixture("tests/fixtures/python_security.toml");
}
