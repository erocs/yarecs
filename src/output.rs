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
// Scan metadata
// ---------------------------------------------------------------------------

/// Provenance information embedded in output formats that support it.
pub struct ScanMetadata<'a> {
    /// Rule config files that were loaded (from `--config`).
    pub configs: &'a [PathBuf],
    /// Reconstructed command line (`std::env::args().collect().join(" ")`).
    pub command_line: &'a str,
}

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
    meta: &ScanMetadata,
) -> io::Result<()> {
    match format {
        OutputFormat::Text  => write_text(out, matches, meta),
        OutputFormat::Json  => write_json(out, matches, meta),
        OutputFormat::Csv   => write_csv(out, matches),
        OutputFormat::Sarif => write_sarif(out, matches, meta),
    }
}

// ---------------------------------------------------------------------------
// Text
// ---------------------------------------------------------------------------

fn write_text(out: &mut dyn Write, matches: &[ScanMatch], meta: &ScanMetadata) -> io::Result<()> {
    // Header: rule files and command used to produce this output.
    let configs = meta.configs.iter()
        .map(|p| p.to_string_lossy())
        .collect::<Vec<_>>()
        .join(", ");
    writeln!(out, "yarecs scan — config: {configs}")?;
    writeln!(out, "command: {}", meta.command_line)?;
    writeln!(out)?;

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
        // Indent every line of the snippet (multiline matches span several lines).
        let indented = m.snippet.replace('\n', "\n  ");
        writeln!(out, "  {}", indented)?;
        if let Some(ref v) = m.ai_verdict {
            let label = if v.is_false_positive { "FALSE POSITIVE" } else { "CONFIRMED" };
            writeln!(out, "  [AI: {} \u{2014} {}]", label, v.reasoning)?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON
// ---------------------------------------------------------------------------

/// Encode `s` as a JSON string literal (double-quoted, RFC 8259 §7 compliant).
///
/// Rust's `{:?}` debug format emits `\u{XXXX}` for non-ASCII characters, which
/// is Rust syntax and **not** valid JSON.  This function emits `\uXXXX` (exactly
/// 4 hex digits, no braces) for control characters and passes printable UTF-8
/// through literally (permitted by RFC 8259 §8.1).
fn json_str(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for ch in s.chars() {
        match ch {
            '"'  => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c    => out.push(c),
        }
    }
    out.push('"');
    out
}

fn write_json(out: &mut dyn Write, matches: &[ScanMatch], meta: &ScanMetadata) -> io::Result<()> {
    // Metadata object wraps the matches array so consumers can identify the scan.
    let cmd = json_str(meta.command_line);
    writeln!(out, "{{")?;
    writeln!(out, "  \"metadata\": {{")?;
    write!(out, "    \"configs\": [")?;
    for (i, p) in meta.configs.iter().enumerate() {
        let comma = if i + 1 < meta.configs.len() { "," } else { "" };
        write!(out, "{}{comma}", json_str(&p.to_string_lossy()))?;
    }
    writeln!(out, "],")?;
    writeln!(out, "    \"command\": {cmd}")?;
    writeln!(out, "  }},")?;
    writeln!(out, "  \"matches\": [")?;
    for (i, m) in matches.iter().enumerate() {
        let scope = m.scope_path.join("::");
        let comma = if i + 1 < matches.len() { "," } else { "" };
        // Hand-rolled JSON to avoid a serde_json dependency.
        // Use json_str() rather than {:?} — Rust's debug format emits \u{XXXX}
        // which is not valid JSON (RFC 8259 §7 requires \uXXXX, no braces).
        let r    = json_str(&m.rule_name);
        let f    = json_str(&m.file.to_string_lossy());
        let s    = json_str(&scope);
        let sev  = json_str(&m.severity.to_string());
        let ctx  = json_str(&m.context.to_string());
        let msg  = json_str(&m.message);
        let mat  = json_str(&m.matched_text);
        let snip = json_str(&m.snippet);
        let ai = match &m.ai_verdict {
            Some(v) => format!(
                "{{\"is_false_positive\":{},\"reasoning\":{}}}",
                v.is_false_positive,
                json_str(&v.reasoning)
            ),
            None => "null".to_string(),
        };
        writeln!(
            out,
            "    {{\"rule\":{r},\"file\":{f},\"line\":{l},\"col\":{c},\
             \"scope\":{s},\"severity\":{sev},\"context\":{ctx},\
             \"message\":{msg},\"match\":{mat},\"snippet\":{snip},\
             \"ai_verdict\":{ai}}}{comma}",
            l = m.line,
            c = m.column,
        )?;
    }
    writeln!(out, "  ]")?;
    writeln!(out, "}}")?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CSV (RFC 4180)
// ---------------------------------------------------------------------------

fn write_csv(out: &mut dyn Write, matches: &[ScanMatch]) -> io::Result<()> {
    writeln!(out, "rule,file,line,col,severity,scope,context,message,match,snippet,ai_verdict,ai_reasoning")?;
    for m in matches {
        let (ai_verdict, ai_reasoning) = match &m.ai_verdict {
            Some(v) => (
                if v.is_false_positive { "false_positive" } else { "confirmed" },
                v.reasoning.as_str(),
            ),
            None => ("", ""),
        };
        writeln!(
            out,
            "{},{},{},{},{},{},{},{},{},{},{},{}",
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
            csv_field(ai_verdict),
            csv_field(ai_reasoning),
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

fn write_sarif(out: &mut dyn Write, matches: &[ScanMatch], meta: &ScanMetadata) -> io::Result<()> {
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
        let id_s  = json_str(id);
        let msg_s = json_str(msg);
        writeln!(out,
            "        {{\"id\": {id_s}, \"shortDescription\": {{\"text\": {msg_s}}}, \
             \"defaultConfiguration\": {{\"level\": \"{}\"}}}}{comma}",
            sarif_level(sev)
        )?;
    }
    writeln!(out, "      ]")?;
    writeln!(out, "    }}}},")?;

    // invocations — captures the command line used for this scan ─────────────
    let cmd_j = json_str(meta.command_line);
    writeln!(out, "    \"invocations\": [{{")?;
    writeln!(out, "      \"commandLine\": {cmd_j},")?;
    writeln!(out, "      \"executionSuccessful\": true")?;
    writeln!(out, "    }}],")?;

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
        let ai_suffix = match &m.ai_verdict {
            Some(v) => {
                let label = if v.is_false_positive { "FALSE POSITIVE" } else { "CONFIRMED" };
                format!(" [AI: {} \u{2014} {}]", label, v.reasoning)
            }
            None => String::new(),
        };
        let full_msg = format!("{} [{}]{}{}", m.message, scope, ctx_suffix, ai_suffix);
        let props = match &m.ai_verdict {
            Some(v) => format!(
                ", \"properties\": {{\"ai_false_positive\": {}, \"ai_reasoning\": {}}}",
                v.is_false_positive,
                json_str(&v.reasoning)
            ),
            None => String::new(),
        };
        let uri = sarif_uri(&m.file);
        let rule_id  = json_str(&m.rule_name);
        let msg_j    = json_str(&full_msg);
        let uri_j    = json_str(&uri);
        let snippet_j = json_str(&m.snippet);
        writeln!(out,
            "      {{\"ruleId\": {rule_id}, \"level\": \"{}\", \
             \"message\": {{\"text\": {msg_j}}}, \
             \"locations\": [{{\"physicalLocation\": {{\"artifactLocation\": \
             {{\"uri\": {uri_j}}}, \"region\": {{\"startLine\": {}, \
             \"startColumn\": {}, \"snippet\": {{\"text\": {snippet_j}}}}}}}}}]{props}}}{comma}",
            sarif_level(&m.severity), m.line, m.column,
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

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::engine::{MatchContext, ScanMatch};
    use crate::rules::Severity;
    use std::path::PathBuf;

    // ── json_str unit tests ──────────────────────────────────────────────────

    #[test]
    fn json_str_plain_ascii() {
        assert_eq!(json_str("hello"), "\"hello\"");
    }

    #[test]
    fn json_str_escapes_double_quote() {
        assert_eq!(json_str(r#"say "hi""#), r#""say \"hi\"""#);
    }

    #[test]
    fn json_str_escapes_backslash() {
        assert_eq!(json_str(r"a\b"), r#""a\\b""#);
    }

    #[test]
    fn json_str_escapes_newline_tab_cr() {
        assert_eq!(json_str("a\nb\tc\r"), r#""a\nb\tc\r""#);
    }

    #[test]
    fn json_str_escapes_control_chars_as_u_xxxx() {
        // U+0001 and U+001F — must be \u0001 / \u001f, no curly braces
        assert_eq!(json_str("\x01"), "\"\\u0001\"");
        assert_eq!(json_str("\x1f"), "\"\\u001f\"");
    }

    /// Regression: Rust's {:?} emits \u{f800}; json_str must emit the literal
    /// UTF-8 character (or a valid \uXXXX escape without braces).
    /// U+F800 is a valid Unicode code point — JSON allows it as UTF-8.
    #[test]
    fn json_str_non_ascii_no_curly_brace_escape() {
        let ch = '\u{f800}';
        let result = json_str(&ch.to_string());
        // Must not contain the Rust debug escape syntax \u{...}
        assert!(!result.contains("\\u{"), "got: {result}");
        // Must be a valid quoted string containing the literal character
        assert!(result.starts_with('"') && result.ends_with('"'));
        let inner = &result[1..result.len() - 1];
        // The character should appear literally (UTF-8 pass-through)
        assert!(inner.contains(ch), "got: {result}");
    }

    #[test]
    fn json_str_multibyte_unicode_passthrough() {
        // Emoji (4-byte UTF-8) and CJK (3-byte) pass through literally
        assert_eq!(json_str("αβγ"), "\"αβγ\"");
        assert_eq!(json_str("日本語"), "\"日本語\"");
        assert_eq!(json_str("🎉"), "\"🎉\"");
    }

    #[test]
    fn json_str_empty() {
        assert_eq!(json_str(""), "\"\"");
    }

    // ── helpers ──────────────────────────────────────────────────────────────

    fn make_match(snippet: &str) -> ScanMatch {
        ScanMatch {
            rule_name:    "test_rule".to_string(),
            file:         PathBuf::from("src/foo.rs"),
            line:         1,
            column:       1,
            scope_path:   vec![],
            matched_text: "match".to_string(),
            snippet:      snippet.to_string(),
            ai_snippet:   String::new(),
            message:      "msg".to_string(),
            severity:     Severity::Warning,
            context:      MatchContext::Code,
            ai_verdict:   None,
        }
    }

    fn test_meta() -> ScanMetadata<'static> {
        ScanMetadata { configs: &[], command_line: "yarecs test" }
    }

    fn collect(matches: &[ScanMatch], fmt: OutputFormat) -> String {
        let mut buf = Vec::new();
        write_results(&mut buf, &fmt, matches, &test_meta()).unwrap();
        String::from_utf8(buf).unwrap()
    }

    // ── JSON output tests ────────────────────────────────────────────────────

    #[test]
    fn json_output_valid_for_non_ascii_snippet() {
        // U+F800 in the snippet must not produce \u{f800} (invalid JSON)
        let m = make_match("md5.Sum([]byte(\"Hello, \u{f800}!\"))");
        let out = collect(&[m], OutputFormat::Json);
        assert!(!out.contains("\\u{"), "Rust debug escape leaked into JSON: {out}");
        // Must be parseable — do a structural sanity check
        assert!(out.contains("\"snippet\":"));
    }

    #[test]
    fn json_output_escapes_backslash_in_snippet() {
        // A snippet with a literal backslash (e.g. from a Go string) must be
        // double-escaped so the result is valid JSON (\\ in output)
        let m = make_match(r"fmt.Println(\n)");
        let out = collect(&[m], OutputFormat::Json);
        assert!(out.contains("\\\\"), "backslash not double-escaped: {out}");
    }

    #[test]
    fn json_output_escapes_quotes_in_message() {
        let mut m = make_match("x");
        m.message = r#"use "safe" instead"#.to_string();
        let out = collect(&[m], OutputFormat::Json);
        assert!(out.contains(r#"\"safe\""#), "quotes not escaped: {out}");
        assert!(!out.contains("\\u{"), "Rust debug escape in output: {out}");
    }

    // ── SARIF output tests ───────────────────────────────────────────────────

    #[test]
    fn sarif_output_valid_for_non_ascii_snippet() {
        let m = make_match("md5.Sum([]byte(\"Hello, \u{f800}!\"))");
        let out = collect(&[m], OutputFormat::Sarif);
        assert!(!out.contains("\\u{"), "Rust debug escape in SARIF: {out}");
        assert!(out.contains("\"snippet\""));
    }

    #[test]
    fn sarif_output_escapes_backslash_in_uri() {
        // Windows-style path — sarif_uri replaces \ with /, but if any \ remains
        // it must be escaped. Verify no raw backslash appears in the uri field.
        let mut m = make_match("x");
        m.file = PathBuf::from(r"src\subdir\foo.rs");
        let out = collect(&[m], OutputFormat::Sarif);
        // sarif_uri converts to forward slashes
        assert!(out.contains("src/subdir/foo.rs"), "path not normalized: {out}");
    }

    #[test]
    fn sarif_output_structure_contains_required_keys() {
        let m = make_match("snippet text");
        let out = collect(&[m], OutputFormat::Sarif);
        for key in &["$schema", "version", "runs", "tool", "results", "ruleId", "level",
                     "message", "locations", "physicalLocation", "region", "snippet"] {
            assert!(out.contains(key), "missing key {key} in SARIF output");
        }
    }

    // ── metadata embedding tests ─────────────────────────────────────────────

    #[test]
    fn text_output_has_metadata_header() {
        let configs = vec![PathBuf::from("rules/foo.toml"), PathBuf::from("rules/bar.toml")];
        let meta = ScanMetadata { configs: &configs, command_line: "yarecs src/ -c rules/foo.toml" };
        let m = make_match("x");
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Text, &[m], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("yarecs scan"), "missing header: {out}");
        assert!(out.contains("rules/foo.toml"), "config not in header: {out}");
        assert!(out.contains("rules/bar.toml"), "second config not in header: {out}");
        assert!(out.contains("yarecs src/ -c rules/foo.toml"), "command not in header: {out}");
        // Matches still appear after the header
        assert!(out.contains("src/foo.rs"), "match missing after header: {out}");
    }

    #[test]
    fn text_output_empty_matches_still_has_header() {
        let configs = vec![PathBuf::from("rules.toml")];
        let meta = ScanMetadata { configs: &configs, command_line: "yarecs ." };
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Text, &[], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("yarecs scan"), "header missing for empty results: {out}");
        assert!(out.contains("rules.toml"), "config missing for empty results: {out}");
    }

    #[test]
    fn json_output_has_metadata_field() {
        let configs = vec![PathBuf::from("rules/foo.toml")];
        let meta = ScanMetadata { configs: &configs, command_line: "yarecs src/ -c rules/foo.toml" };
        let m = make_match("x");
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Json, &[m], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\"metadata\""), "metadata key missing: {out}");
        assert!(out.contains("\"configs\""), "configs key missing: {out}");
        assert!(out.contains("\"command\""), "command key missing: {out}");
        assert!(out.contains("rules/foo.toml"), "config path missing: {out}");
        assert!(out.contains("\"matches\""), "matches key missing: {out}");
        // Match data still present
        assert!(out.contains("\"rule\""), "rule field missing: {out}");
    }

    #[test]
    fn json_metadata_command_is_escaped() {
        // A command with backslashes (Windows paths) must be valid JSON.
        let meta = ScanMetadata {
            configs: &[],
            command_line: r#"yarecs "C:\src\my project" -c rules\foo.toml"#,
        };
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Json, &[], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        // No raw backslashes inside a JSON string value
        assert!(out.contains("\\\\"), "backslash not escaped in command: {out}");
    }

    #[test]
    fn sarif_output_has_invocations() {
        let configs = vec![PathBuf::from("rules/foo.toml")];
        let meta = ScanMetadata { configs: &configs, command_line: "yarecs src/ -c rules/foo.toml" };
        let m = make_match("x");
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Sarif, &[m], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.contains("\"invocations\""), "invocations missing: {out}");
        assert!(out.contains("\"commandLine\""), "commandLine missing: {out}");
        assert!(out.contains("\"executionSuccessful\""), "executionSuccessful missing: {out}");
        assert!(out.contains("yarecs src/ -c rules/foo.toml"), "command text missing: {out}");
    }

    fn make_match_with_verdict(snippet: &str, is_fp: bool, reasoning: &str) -> ScanMatch {
        use crate::engine::AiVerdict;
        let mut m = make_match(snippet);
        m.ai_verdict = Some(AiVerdict { is_false_positive: is_fp, reasoning: reasoning.to_string() });
        m
    }

    // ── AI verdict in CSV ────────────────────────────────────────────────────

    #[test]
    fn csv_output_includes_ai_verdict_columns_in_header() {
        let m = make_match("x");
        let out = collect(&[m], OutputFormat::Csv);
        assert!(out.starts_with("rule,file,line,col,severity,scope,context,message,match,snippet,ai_verdict,ai_reasoning"),
            "header missing ai columns: {out}");
    }

    #[test]
    fn csv_output_false_positive_verdict() {
        let m = make_match_with_verdict("x", true, "benign usage");
        let out = collect(&[m], OutputFormat::Csv);
        assert!(out.contains("false_positive"), "verdict label missing: {out}");
        assert!(out.contains("benign usage"), "reasoning missing: {out}");
    }

    #[test]
    fn csv_output_confirmed_verdict() {
        let m = make_match_with_verdict("x", false, "real issue");
        let out = collect(&[m], OutputFormat::Csv);
        assert!(out.contains("confirmed"), "verdict label missing: {out}");
        assert!(out.contains("real issue"), "reasoning missing: {out}");
    }

    #[test]
    fn csv_output_no_verdict_has_empty_ai_columns() {
        let m = make_match("x");
        let out = collect(&[m], OutputFormat::Csv);
        // Data row ends with two empty comma-separated fields
        assert!(out.contains(",,\n") || out.ends_with(",,\n") || out.contains(",,,"),
            "empty ai columns not present: {out}");
    }

    // ── AI verdict in SARIF ──────────────────────────────────────────────────

    #[test]
    fn sarif_output_ai_verdict_in_message_and_properties() {
        let m = make_match_with_verdict("x", true, "benign usage");
        let out = collect(&[m], OutputFormat::Sarif);
        assert!(out.contains("FALSE POSITIVE"), "AI label missing from message: {out}");
        assert!(out.contains("benign usage"), "reasoning missing: {out}");
        assert!(out.contains("\"ai_false_positive\": true"), "properties missing: {out}");
        assert!(out.contains("\"ai_reasoning\""), "ai_reasoning key missing: {out}");
    }

    #[test]
    fn sarif_output_confirmed_verdict_in_message_and_properties() {
        let m = make_match_with_verdict("x", false, "real issue");
        let out = collect(&[m], OutputFormat::Sarif);
        assert!(out.contains("CONFIRMED"), "AI label missing from message: {out}");
        assert!(out.contains("real issue"), "reasoning missing: {out}");
        assert!(out.contains("\"ai_false_positive\": false"), "properties missing: {out}");
    }

    #[test]
    fn sarif_output_no_verdict_has_no_properties() {
        let m = make_match("x");
        let out = collect(&[m], OutputFormat::Sarif);
        assert!(!out.contains("\"properties\""), "unexpected properties in output: {out}");
        assert!(!out.contains("ai_false_positive"), "unexpected ai field: {out}");
    }

    #[test]
    fn csv_output_has_no_metadata_header() {
        // CSV has no metadata section — header row is always the column names.
        let configs = vec![PathBuf::from("rules.toml")];
        let meta = ScanMetadata { configs: &configs, command_line: "yarecs ." };
        let m = make_match("x");
        let mut buf = Vec::new();
        write_results(&mut buf, &OutputFormat::Csv, &[m], &meta).unwrap();
        let out = String::from_utf8(buf).unwrap();
        assert!(out.starts_with("rule,file,"), "CSV should start with column header: {out}");
        assert!(!out.contains("yarecs scan"), "CSV must not have metadata header: {out}");
    }
}
