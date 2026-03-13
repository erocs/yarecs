//! Output formatters for scan results.
//!
//! All formatters accept a `&mut dyn Write` so they work identically against
//! stdout, a `BufWriter<File>`, or any other sink.  Add new formats by
//! implementing a `write_*` function and wiring it into `write_results`.

use std::collections::BTreeMap;
use std::io::{self, Write};
use std::path::PathBuf;

use crate::engine::{MatchContext, ScanMatch};
use crate::rules::Severity;

// ---------------------------------------------------------------------------
// Format enum
// ---------------------------------------------------------------------------

/// Output format selected via `--format`.
#[derive(Clone, clap::ValueEnum)]
pub enum OutputFormat {
    /// Human-readable text (default)
    Text,
    /// JSON array — one object per match
    Json,
    /// RFC 4180 CSV with a header row
    Csv,
    /// SARIF v2.1.0 — compatible with GitHub Code Scanning, VS Code, Azure DevOps
    Sarif,
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

pub fn write_results(
    out: &mut dyn Write,
    format: &OutputFormat,
    matches: &[ScanMatch],
) -> io::Result<()> {
    match format {
        OutputFormat::Text  => write_text(out, matches),
        OutputFormat::Json  => write_json(out, matches),
        OutputFormat::Csv   => write_csv(out, matches),
        OutputFormat::Sarif => write_sarif(out, matches),
    }
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn write_text(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    for m in matches {
        let scope = if m.scope_path.is_empty() {
            "<global>".to_string()
        } else {
            m.scope_path.join("::")
        };
        // Append context tag only for non-code matches to keep the common case clean.
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
        writeln!(out, "  {}", m.snippet)?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

fn write_json(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    writeln!(out, "[")?;
    for (i, m) in matches.iter().enumerate() {
        let scope = m.scope_path.join("::");
        let comma = if i + 1 < matches.len() { "," } else { "" };
        // Hand-rolled JSON to avoid a serde_json dependency.
        writeln!(
            out,
            "  {{\"rule\":{r:?},\"file\":{f:?},\"line\":{l},\"col\":{c},\
             \"scope\":{s:?},\"severity\":{sev:?},\"context\":{ctx:?},\
             \"message\":{msg:?},\"match\":{mat:?},\"snippet\":{snip:?}}}{comma}",
            r    = m.rule_name,
            f    = m.file.to_string_lossy(),
            l    = m.line,
            c    = m.column,
            s    = scope,
            sev  = m.severity.to_string(),
            ctx  = m.context.to_string(),
            msg  = m.message,
            mat  = m.matched_text,
            snip = m.snippet,
        )?;
    }
    writeln!(out, "]")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CSV (RFC 4180)
// ---------------------------------------------------------------------------

fn write_csv(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    writeln!(out, "rule,file,line,col,severity,scope,context,message,match,snippet")?;
    for m in matches {
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{}",
            csv_field(&m.rule_name),
            csv_field(&m.file.to_string_lossy()),
            m.line,
            m.column,
            csv_field(&m.severity.to_string()),
            csv_field(&m.scope_path.join("::")),
            csv_field(&m.context.to_string()),
            csv_field(&m.message),
            csv_field(&m.matched_text),
            csv_field(&m.snippet),
        )?;
    }
    Ok(())
}

/// Wrap `s` in double-quotes if it contains a comma, double-quote, or line
/// ending.  Embedded double-quotes are escaped by doubling them (RFC 4180 §2).
fn csv_field(s: &str) -> String {
    if s.contains([',', '"', '\n', '\r']) {
        format!("\"{}\"", s.replace('"', "\"\""))
    } else {
        s.to_string()
    }
}

// ---------------------------------------------------------------------------
// SARIF v2.1.0
// ---------------------------------------------------------------------------

fn write_sarif(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    // Collect unique rules in deterministic order (BTreeMap sorts by key).
    // Value is (message, severity) from the first occurrence of each rule ID.
    let mut rule_meta: BTreeMap<&str, (&str, &Severity)> = BTreeMap::new();
    for m in matches {
        rule_meta.entry(&m.rule_name).or_insert((&m.message, &m.severity));
    }
    let rule_list: Vec<_> = rule_meta.iter().collect();

    writeln!(out, "{{")?;
    writeln!(out, "  \"$schema\": \"https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json\",")?;
    writeln!(out, "  \"version\": \"2.1.0\",")?;
    writeln!(out, "  \"runs\": [{{")?;

    // tool.driver ────────────────────────────────────────────────────────────
    writeln!(out, "    \"tool\": {{\"driver\": {{")?;
    writeln!(out, "      \"name\": \"yarecs\",")?;
    writeln!(out, "      \"rules\": [")?;
    for (i, (id, (msg, sev))) in rule_list.iter().enumerate() {
        let comma = if i + 1 < rule_list.len() { "," } else { "" };
        writeln!(out,
            "        {{\"id\": {id:?}, \"shortDescription\": {{\"text\": {msg:?}}}, \
             \"defaultConfiguration\": {{\"level\": \"{}\"}}}}{comma}",
            sarif_level(sev)
        )?;
    }
    writeln!(out, "      ]")?;
    writeln!(out, "    }}}},")?;

    // results ────────────────────────────────────────────────────────────────
    writeln!(out, "    \"results\": [")?;
    for (i, m) in matches.iter().enumerate() {
        let comma = if i + 1 < matches.len() { "," } else { "" };
        let scope = m.scope_path.join("::");
        let ctx_suffix = match m.context {
            MatchContext::Code          => String::new(),
            MatchContext::Comment       => " {in comment}".to_string(),
            MatchContext::StringLiteral => " {in string}".to_string(),
        };
        // Combine message + scope + context into a single human-readable string
        // so SARIF viewers surface everything without needing custom columns.
        let full_msg = format!("{} [{}]{}", m.message, scope, ctx_suffix);
        let uri = sarif_uri(&m.file);
        writeln!(out,
            "      {{\"ruleId\": {:?}, \"level\": \"{}\", \
             \"message\": {{\"text\": {full_msg:?}}}, \
             \"locations\": [{{\"physicalLocation\": {{\"artifactLocation\": \
             {{\"uri\": {uri:?}}}, \"region\": {{\"startLine\": {}, \
             \"startColumn\": {}, \"snippet\": {{\"text\": {:?}}}}}}}}}]}}{comma}",
            m.rule_name, sarif_level(&m.severity), m.line, m.column, m.snippet,
        )?;
    }
    writeln!(out, "    ]")?;
    writeln!(out, "  }}]")?;
    writeln!(out, "}}")?;
    Ok(())
}

fn sarif_level(sev: &Severity) -> &'static str {
    match sev {
        Severity::Error   => "error",
        Severity::Warning => "warning",
        Severity::Info    => "note",
    }
}

/// Convert a path to a forward-slash URI for SARIF `artifactLocation.uri`.
/// On Windows, backslashes are replaced with forward slashes.
fn sarif_uri(path: &PathBuf) -> String {
    path.to_string_lossy().replace('\\', "/")
}
