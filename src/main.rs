mod engine;
mod lexer;
mod rules;
mod scope;

use anyhow::{Context, Result};
use clap::Parser;
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

    for input_path in &args.paths {
        for entry in WalkDir::new(input_path)
            .into_iter()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_type().is_file())
        {
            let path = entry.path();
            let ext = path.extension().and_then(|e| e.to_str()).unwrap_or("");
            if !extensions.iter().any(|&e| e == ext) {
                continue;
            }

            let source = std::fs::read_to_string(path)
                .with_context(|| format!("cannot read {}", path.display()))?;

            let lex     = lexer::Lexer::new(&source).tokenize();
            let profile = profile_for_ext(ext);
            let tree    = ScopeParser::new(profile).parse(&lex.tokens, source.len());

            if args.dump_scopes {
                eprintln!("=== {} ===", path.display());
                print_scope_tree(&tree, 0);
                continue;
            }

            let file_matches = engine::scan_file(&source, path, &tree, &rules, &lex);
            all_matches.extend(file_matches);
            file_count += 1;
        }
    }

    if !args.dump_scopes {
        match args.format {
            OutputFormat::Json => print_json(&all_matches),
            OutputFormat::Text => print_text(&all_matches),
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

fn print_text(matches: &[ScanMatch]) {
    for m in matches {
        let scope = if m.scope_path.is_empty() {
            "<global>".to_string()
        } else {
            m.scope_path.join("::")
        };
        // Append {comment} / {string} tag only when not plain code, so the
        // common case stays clean and flagged-in-comment matches are obvious.
        let ctx_tag = match m.context {
            MatchContext::Code          => String::new(),
            MatchContext::Comment       => "  {in comment}".to_string(),
            MatchContext::StringLiteral => "  {in string}".to_string(),
        };
        println!(
            "{}:{}:{}: [{}] {} [{}]{}",
            m.file.display(), m.line, m.column,
            m.severity, m.message, scope, ctx_tag,
        );
        println!("  match: {:?}", m.matched_text);
    }
}

fn print_json(matches: &[ScanMatch]) {
    println!("[");
    for (i, m) in matches.iter().enumerate() {
        let scope = m.scope_path.join("::");
        let comma = if i + 1 < matches.len() { "," } else { "" };
        // Minimal hand-rolled JSON to avoid pulling in serde_json
        println!(
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
        );
    }
    println!("]");
}
