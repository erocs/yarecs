mod engine;
mod lexer;
mod output;
mod rules;
mod scope;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{self, BufWriter};
use std::path::PathBuf;
use walkdir::WalkDir;

use engine::ScanMatch;
use output::OutputFormat;
use rules::{load_rules, Severity};
use scope::{print_scope_tree, profile_for_ext, ScopeParser};

// ---------------------------------------------------------------------------
// CLI
// ---------------------------------------------------------------------------

/// Scope-aware regex scanner for C-like languages.
///
/// Rules are defined in a TOML config file.  Each rule specifies a regex
/// pattern and an optional scope filter (e.g. `**::MyClass::*`) that
/// constrains where the pattern is searched.
#[derive(Parser)]
#[command(name = "yarecs", version, about)]
struct Args {
    /// Rules config file(s) (TOML); may be repeated to merge multiple rule sets
    #[arg(short, long, default_value = "rules.toml")]
    config: Vec<PathBuf>,

    /// Files or directories to scan
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// File extensions to include (comma-separated)
    #[arg(short, long, default_value = "c,cpp,cc,cxx,h,hpp,hh,cs,java,go,rs,kt,kts,swift")]
    extensions: String,

    /// Print the scope tree for each file instead of running rules
    #[arg(long)]
    dump_scopes: bool,

    /// Output format: text | json | csv | sarif
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Write results to this file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Directory name(s) to exclude from the scan; may be repeated.
    /// Matched against each directory component name (not the full path).
    /// Supports `*` as a wildcard, e.g. `--exclude _build --exclude target --exclude _*`.
    #[arg(short = 'x', long)]
    exclude: Vec<String>,

    /// Scan every file regardless of extension (overrides --extensions).
    /// Useful for credential scanning where secrets can appear in any text file
    /// (.env, Makefile, Dockerfile, files with no extension, etc.).
    /// Files that cannot be read as UTF-8 are still skipped with a warning.
    #[arg(long)]
    all_files: bool,
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Match `name` against `pattern` where `*` matches any sequence of characters
/// (excluding path separators).  Used for `--exclude` directory filtering.
fn glob_match(pattern: &str, name: &str) -> bool {
    let pat: Vec<char> = pattern.chars().collect();
    let nam: Vec<char> = name.chars().collect();
    let mut dp = vec![vec![false; nam.len() + 1]; pat.len() + 1];
    dp[0][0] = true;
    for i in 1..=pat.len() {
        if pat[i - 1] == '*' { dp[i][0] = dp[i - 1][0]; }
    }
    for i in 1..=pat.len() {
        for j in 1..=nam.len() {
            dp[i][j] = if pat[i - 1] == '*' {
                dp[i - 1][j] || dp[i][j - 1]
            } else {
                dp[i - 1][j - 1] && (pat[i - 1] == nam[j - 1])
            };
        }
    }
    dp[pat.len()][nam.len()]
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

fn main() -> Result<()> {
    let args = Args::parse();

    let extensions: Vec<&str> = args.extensions.split(',').map(str::trim).collect();

    let rules = if args.dump_scopes {
        Vec::new() // no rules needed for scope dump
    } else {
        let mut all_rules = Vec::new();
        for config_path in &args.config {
            let mut r = load_rules(config_path)?;
            all_rules.append(&mut r);
        }
        all_rules
    };

    let mut all_matches: Vec<ScanMatch> = Vec::new();
    let mut file_count = 0usize;
    let mut last_dir: Option<PathBuf> = None;

    for input_path in &args.paths {
        for entry in WalkDir::new(input_path)
            .into_iter()
            .filter_entry(|e| {
                // Prune excluded directories before descending into them.
                if e.file_type().is_dir() {
                    if let Some(name) = e.file_name().to_str() {
                        if args.exclude.iter().any(|pat| glob_match(pat, name)) {
                            return false;
                        }
                    }
                }
                true
            })
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();

            // Print a progress line whenever we descend into a new directory.
            let dir = path.parent().map(|p| p.to_path_buf());
            if dir != last_dir {
                if let Some(ref d) = dir {
                    eprintln!("  {}/", d.display());
                }
                last_dir = dir;
            }

            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !args.all_files && !extensions.iter().any(|&e| e == ext) {
                continue;
            }

            let raw = match std::fs::read_to_string(path) {
                Ok(s) => s,
                Err(e) => {
                    // Non-UTF-8 files (Latin-1, UTF-16, binary) are skipped with a
                    // warning so one bad file does not abort the entire scan.
                    eprintln!("warning: skipping {} ({})", path.display(), e);
                    continue;
                }
            };
            // Strip the UTF-8 BOM (U+FEFF, encoded as EF BB BF) if present.
            // MSVC-generated headers commonly include it; leaving it in causes
            // byte-index panics when source[1..] is indexed inside body_range.
            let source = raw.strip_prefix('\u{FEFF}').unwrap_or(&raw);

            let lex     = lexer::Lexer::new(source).tokenize();
            let profile = profile_for_ext(ext);
            let tree    = ScopeParser::new(profile).parse(&lex.tokens, source.len());

            if args.dump_scopes {
                eprintln!("=== {} ===", path.display());
                print_scope_tree(&tree, 0);
                continue;
            }

            let file_matches = engine::scan_file(source, path, &tree, &rules, &lex);
            all_matches.extend(file_matches);
            file_count += 1;
        }
    }

    if !args.dump_scopes {
        // Open output destination: a file if --output was given, otherwise stdout.
        if let Some(ref out_path) = args.output {
            let file = std::fs::File::create(out_path)
                .with_context(|| format!("cannot create output file {}", out_path.display()))?;
            output::write_results(&mut BufWriter::new(file), &args.format, &all_matches)?;
        } else {
            output::write_results(&mut BufWriter::new(io::stdout()), &args.format, &all_matches)?;
        }

        let errors = all_matches.iter().filter(|m| m.severity == Severity::Error).count();
        eprintln!(
            "\nScanned {} file(s) — {} match(es) ({} error(s))",
            file_count,
            all_matches.len(),
            errors,
        );

        if errors > 0 {
            std::process::exit(1);
        }
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::glob_match;

    #[test]
    fn exact_match() {
        assert!(glob_match("target", "target"));
        assert!(glob_match("_build", "_build"));
    }

    #[test]
    fn exact_no_match() {
        assert!(!glob_match("target", "targets"));
        assert!(!glob_match("target", "my_target"));
    }

    #[test]
    fn wildcard_prefix() {
        assert!(glob_match("_*", "_build"));
        assert!(glob_match("_*", "_cache"));
        assert!(!glob_match("_*", "build"));
    }

    #[test]
    fn wildcard_suffix() {
        assert!(glob_match("*_test", "my_test"));
        assert!(!glob_match("*_test", "my_tests"));
    }

    #[test]
    fn wildcard_only() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
    }

    #[test]
    fn wildcard_infix() {
        assert!(glob_match("test*data", "testdata"));
        assert!(glob_match("test*data", "test_extra_data"));
        assert!(!glob_match("test*data", "testdat"));
    }

    #[test]
    fn empty_pattern_matches_empty_only() {
        assert!(glob_match("", ""));
        assert!(!glob_match("", "x"));
    }
}
