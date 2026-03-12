mod engine;
mod lexer;
mod rules;
mod scope;

use anyhow::{Context, Result};
use clap::Parser;
use std::io::{self, BufWriter, Write};
use std::path::PathBuf;
use walkdir::WalkDir;

use engine::{MatchContext, ScanMatch};
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
#[command(name = "cish-scanner", version, about)]
struct Args {
    /// Rules config file (TOML)
    #[arg(short, long, default_value = "rules.toml")]
    config: PathBuf,

    /// Files or directories to scan
    #[arg(required = true)]
    paths: Vec<PathBuf>,

    /// File extensions to include (comma-separated)
    #[arg(short, long, default_value = "c,cpp,cc,cxx,h,hpp,hh,cs,java,go,rs,kt,kts,swift")]
    extensions: String,

    /// Print the scope tree for each file instead of running rules
    #[arg(long)]
    dump_scopes: bool,

    /// Output format: text | json
    #[arg(short, long, default_value = "text")]
    format: OutputFormat,

    /// Write results to this file instead of stdout
    #[arg(short, long)]
    output: Option<PathBuf>,
}

#[derive(Clone, clap::ValueEnum)]
enum OutputFormat {
    Text,
    Json,
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
        load_rules(&args.config)?
    };

    let mut all_matches: Vec<ScanMatch> = Vec::new();
    let mut file_count = 0usize;
    let mut last_dir: Option<PathBuf> = None;

    for input_path in &args.paths {
        for entry in WalkDir::new(input_path)
            .into_iter()
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
            if !extensions.iter().any(|&e| e == ext) {
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
            write_results(&mut BufWriter::new(file), &args.format, &all_matches)?;
        } else {
            write_results(&mut BufWriter::new(io::stdout()), &args.format, &all_matches)?;
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
// Output formatters
// ---------------------------------------------------------------------------

fn write_results(out: &mut dyn Write, format: &OutputFormat, matches: &[ScanMatch]) -> Result<()> {
    match format {
        OutputFormat::Text => write_text(out, matches)?,
        OutputFormat::Json => write_json(out, matches)?,
    }
    Ok(())
}

fn write_text(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    for m in matches {
        let scope = if m.scope_path.is_empty() {
            "<global>".to_string()
        } else {
            m.scope_path.join("::")
        };
        // Append {comment} / {string} tag only when not plain code, so the
        // common case stays clean and flagged-in-comment matches are obvious.
        let ctx_tag = match m.context {
            MatchContext::Code          => "",
            MatchContext::Comment       => "  {in comment}",
            MatchContext::StringLiteral => "  {in string}",
        };
        writeln!(
            out,
            "{}:{}:{}: [{}] {} [{}]{}",
            m.file.display(), m.line, m.column,
            m.severity, m.message, scope, ctx_tag,
        )?;
        writeln!(out, "  match: {:?}", m.matched_text)?;
    }
    Ok(())
}

fn write_json(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    writeln!(out, "[")?;
    for (i, m) in matches.iter().enumerate() {
        let scope = m.scope_path.join("::");
        let comma = if i + 1 < matches.len() { "," } else { "" };
        // Minimal hand-rolled JSON to avoid pulling in serde_json.
        writeln!(
            out,
            "  {{\"rule\":{r:?},\"file\":{f:?},\"line\":{l},\"col\":{c},\
             \"scope\":{s:?},\"severity\":{sev:?},\"context\":{ctx:?},\
             \"message\":{msg:?},\"match\":{mat:?}}}{comma}",
            r   = m.rule_name,
            f   = m.file.to_string_lossy(),
            l   = m.line,
            c   = m.column,
            s   = scope,
            sev = m.severity.to_string(),
            ctx = m.context.to_string(),
            msg = m.message,
            mat = m.matched_text,
        )?;
    }
    writeln!(out, "]")?;
    Ok(())
}

