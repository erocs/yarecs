//! Scan engine: walks the scope tree and applies rules to source text.
//!
//! ## Algorithm overview
//!
//! For each rule the engine performs a **post-order DFS** over the [`ScopeNode`] tree.
//! Post-order means inner (deeper) scopes are evaluated before their parents, which
//! lets the engine claim byte positions in a `seen: HashSet<usize>` as each scope is
//! processed.  When the parent scope later searches the same byte range, already-claimed
//! positions are skipped — effectively attributing every match to the *innermost* scope
//! that encloses it, regardless of how the scope filter is written.
//!
//! ## Chain evaluation
//!
//! After a trigger pattern matches, [`chain_satisfied`] checks every [`ChainedPattern`]
//! in the rule's `chain` list.  All conditions must hold (AND semantics).  Each
//! condition defines a *search range* derived from the trigger position and the
//! relationship kind (`After`, `Before`, `AnywhereInMethod`, `AnywhereInClass`,
//! `AnywhereInNamespace`).  For the class/namespace variants, the engine walks the
//! `ancestors` stack that is threaded through the DFS to locate the nearest enclosing
//! scope of the required kind.
//!
//! ## Ancestor tracking
//!
//! `ancestors: &mut Vec<&ScopeNode>` is pushed **before** recursing into children and
//! popped **after**, so that while children execute, their true parent chain is visible.
//! After recursion the current node evaluates itself with only its real ancestors in the
//! vec — the node itself is never present in `ancestors` during its own evaluation.

use std::collections::HashSet;
use std::ops::Range;
use std::path::{Path, PathBuf};

use grep::matcher::Matcher;

use crate::lexer::LexOutput;
use crate::rules::{ChainRelationship, ChainedPattern, Rule, SearchTarget, Severity};
use crate::scope::{ScopeKind, ScopeNode};

// ---------------------------------------------------------------------------
// Match context
// ---------------------------------------------------------------------------

/// Where in the source a match was found, relative to lexical structure.
///
/// Used both to *annotate* results (so users see `{in comment}` tags) and to
/// *filter* them when a rule specifies `search = "comments"` or `search = "code"`.
#[derive(Debug, Clone, PartialEq)]
pub enum MatchContext {
    /// Match falls inside executable code (neither comment nor string literal).
    Code,
    /// Match falls inside a `//` or `/* */` comment.
    Comment,
    /// Match falls inside a quoted string or character literal.
    StringLiteral,
}

impl std::fmt::Display for MatchContext {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MatchContext::Code          => write!(f, "code"),
            MatchContext::Comment       => write!(f, "comment"),
            MatchContext::StringLiteral => write!(f, "string"),
        }
    }
}

// ---------------------------------------------------------------------------
// Match result
// ---------------------------------------------------------------------------

/// Verdict returned by the optional AI false-positive classifier.
#[derive(Debug, Clone)]
pub struct AiVerdict {
    pub is_false_positive: bool,
    pub reasoning: String,
}

/// A single rule match emitted by the engine.
#[derive(Debug)]
pub struct ScanMatch {
    /// Name of the rule that produced this match (from TOML `name = "…"`).
    pub rule_name: String,
    pub file: PathBuf,
    /// 1-based line number of the first byte of the match.
    pub line: usize,
    /// 1-based column (byte offset from start of line) of the first byte.
    pub column: usize,
    /// Scope path components from outermost to innermost, e.g. `["MyNS", "MyClass", "myMethod"]`.
    pub scope_path: Vec<String>,
    /// The exact source text that the trigger regex matched.
    pub matched_text: String,
    /// The full source line containing the match, whitespace-trimmed.
    /// Provides immediate context without requiring a separate file read.
    pub snippet: String,
    pub message: String,
    pub severity: Severity,
    /// Whether the match was found in code, a comment, or a string literal.
    pub context: MatchContext,
    /// Verdict from the optional AI false-positive classifier; `None` if AI was not run.
    pub ai_verdict: Option<AiVerdict>,
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

/// Scan a single source file against all rules and return every match.
///
/// Each rule gets its own independent `seen` set so that scope-filter differences
/// between rules don't cause one rule's deduplication to suppress another's matches.
pub fn scan_file(
    source: &str,
    path: &Path,
    scope_tree: &ScopeNode,
    rules: &[Rule],
    lex: &LexOutput,
) -> Vec<ScanMatch> {
    let mut all_matches = Vec::new();

    for rule in rules {
        let mut seen: HashSet<usize> = HashSet::new();
        let mut current_path: Vec<String> = Vec::new();
        let mut ancestors: Vec<&ScopeNode> = Vec::new();
        scan_rule_postorder(
            source, path, scope_tree, rule,
            &mut current_path, &mut ancestors,
            &mut seen, lex, &mut all_matches,
        );
    }

    all_matches
}

// ---------------------------------------------------------------------------
// Post-order DFS
// ---------------------------------------------------------------------------

/// Recursively scan `node` and all its descendants for one rule, post-order.
///
/// Post-order ensures children add their byte positions to `seen` before the parent
/// searches its (larger) body range, so every match is attributed to the innermost
/// enclosing scope that satisfies the rule's scope filter.
fn scan_rule_postorder<'tree>(
    source: &str,
    path: &Path,
    node: &'tree ScopeNode,
    rule: &Rule,
    current_path: &mut Vec<String>,
    // ancestors of `node`, from outermost to immediate parent
    ancestors: &mut Vec<&'tree ScopeNode>,
    seen: &mut HashSet<usize>,
    lex: &LexOutput,
    out: &mut Vec<ScanMatch>,
) {
    let pushed = if !node.name.is_empty() {
        current_path.push(node.name.clone());
        true
    } else {
        false
    };

    // Recurse into children first (post-order).
    // Push `node` so children can find it as an ancestor.
    ancestors.push(node);
    for child in &node.children {
        scan_rule_postorder(source, path, child, rule, current_path, ancestors, seen, lex, out);
    }
    ancestors.pop();

    // Now evaluate this node — `ancestors` holds only this node's true ancestors.
    let should_scan = match &rule.scope_filter {
        None         => node.kind.is_named(),
        Some(filter) => {
            let refs: Vec<&str> = current_path.iter().map(|s| s.as_str()).collect();
            filter.matches(&refs)
        }
    };

    if should_scan {
        let body = node.body_range();
        if body.start <= body.end && body.end <= source.len() {
            search_scope(source, path, body, rule, current_path, seen, lex, node, ancestors, out);
        }
    }

    if pushed {
        current_path.pop();
    }
}

// ---------------------------------------------------------------------------
// Scope search with chain evaluation
// ---------------------------------------------------------------------------

/// Search one scope body for the rule's trigger pattern, respecting `SearchTarget`,
/// deduplicating via `seen`, and verifying chain conditions before emitting.
fn search_scope<'tree>(
    source: &str,
    path: &Path,
    body: Range<usize>,
    rule: &Rule,
    scope_path: &[String],
    seen: &mut HashSet<usize>,
    lex: &LexOutput,
    current_node: &'tree ScopeNode,
    ancestors: &[&'tree ScopeNode],
    out: &mut Vec<ScanMatch>,
) {
    match rule.search_target {
        SearchTarget::All => {
            let slice = source[body.clone()].as_bytes();
            let _ = rule.matcher.find_iter(slice, |m| {
                let abs = body.start + m.start();
                if seen.insert(abs) {
                    if chain_satisfied(source, abs, abs + m.len(), &body, &rule.chain, current_node, ancestors, lex) {
                        let ctx = classify_position(abs, &lex.comment_ranges, &lex.string_ranges);
                        emit_match(source, path, abs, m.len(), ctx, rule, scope_path, out);
                    }
                }
                true
            });
        }

        SearchTarget::Comments => {
            for cr in ranges_overlapping(&lex.comment_ranges, &body) {
                let slice = source[cr.clone()].as_bytes();
                let _ = rule.matcher.find_iter(slice, |m| {
                    let abs = cr.start + m.start();
                    if seen.insert(abs) {
                        if chain_satisfied(source, abs, abs + m.len(), &body, &rule.chain, current_node, ancestors, lex) {
                            emit_match(source, path, abs, m.len(), MatchContext::Comment, rule, scope_path, out);
                        }
                    }
                    true
                });
            }
        }

        SearchTarget::Code => {
            for gap in code_gaps(&body, &lex.comment_ranges, &lex.string_ranges) {
                let slice = source[gap.clone()].as_bytes();
                let _ = rule.matcher.find_iter(slice, |m| {
                    let abs = gap.start + m.start();
                    if seen.insert(abs) {
                        if chain_satisfied(source, abs, abs + m.len(), &body, &rule.chain, current_node, ancestors, lex) {
                            emit_match(source, path, abs, m.len(), MatchContext::Code, rule, scope_path, out);
                        }
                    }
                    true
                });
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chain evaluation
// ---------------------------------------------------------------------------

/// Returns `true` if every chained pattern is satisfied for this trigger match.
fn chain_satisfied(
    source: &str,
    trigger_start: usize,
    trigger_end: usize,
    body: &Range<usize>,
    chain: &[ChainedPattern],
    current_node: &ScopeNode,
    ancestors: &[&ScopeNode],
    lex: &LexOutput,
) -> bool {
    for cp in chain {
        let search: Range<usize> = match cp.relationship {
            ChainRelationship::After => trigger_end..body.end,
            ChainRelationship::Before => body.start..trigger_start,
            ChainRelationship::AnywhereInMethod => {
                match nearest_of_kind(ancestors, current_node, &[ScopeKind::Function]) {
                    Some(n) => n.body_range(),
                    None    => body.clone(), // no enclosing function; fall back to current scope
                }
            }
            ChainRelationship::AnywhereInClass => {
                match nearest_of_kind(ancestors, current_node, &[ScopeKind::Class, ScopeKind::Struct]) {
                    Some(n) => n.body_range(),
                    None    => return false,
                }
            }
            ChainRelationship::AnywhereInNamespace => {
                match nearest_of_kind(ancestors, current_node, &[ScopeKind::Namespace]) {
                    Some(n) => n.body_range(),
                    None    => return false,
                }
            }
            ChainRelationship::AnywhereInStatement => {
                let bytes = source.as_bytes();
                // Walk backward from the trigger to the nearest statement boundary
                // (`;`, `{`, `}`), skipping positions inside comments or strings.
                // The `loop { break value; }` expression evaluates to the break value.
                let stmt_start: usize = {
                    let mut pos = trigger_start;
                    loop {
                        if pos <= body.start { break body.start; }
                        pos -= 1;
                        if in_any_range(pos, &lex.comment_ranges)
                            || in_any_range(pos, &lex.string_ranges) { continue; }
                        let b = bytes[pos];
                        if b == b';' || b == b'{' || b == b'}' { break pos + 1; }
                    }
                };
                // Walk forward from the trigger end to the next statement boundary.
                let stmt_end: usize = {
                    let mut pos = trigger_end;
                    loop {
                        if pos >= body.end { break body.end; }
                        if in_any_range(pos, &lex.comment_ranges)
                            || in_any_range(pos, &lex.string_ranges) { pos += 1; continue; }
                        let b = bytes[pos];
                        pos += 1;
                        if b == b';' || b == b'{' || b == b'}' { break pos; }
                    }
                };
                stmt_start..stmt_end
            }
        };

        // Clamp to within_lines lines on either side of the trigger, if set.
        let search = if let Some(n) = cp.within_lines {
            let bytes = source.as_bytes();
            let s = retreat_n_lines(bytes, trigger_start, n, body.start).max(search.start);
            let e = advance_n_lines(bytes, trigger_end, n, body.end).min(search.end);
            s..e
        } else {
            search
        };

        if search.start >= search.end || search.end > source.len() {
            return false;
        }

        let haystack = source[search].as_bytes();
        let mut found = false;
        let _ = cp.matcher.find_iter(haystack, |_| { found = true; false });
        // Positive chain: pattern must be present.  Negative (negate=true): must be absent.
        if found == cp.negate {
            return false;
        }
    }
    true
}

/// Find the nearest scope of one of `kinds`, checking `current` first then
/// walking `ancestors` from innermost outward.
fn nearest_of_kind<'a>(
    ancestors: &[&'a ScopeNode],
    current: &'a ScopeNode,
    kinds: &[ScopeKind],
) -> Option<&'a ScopeNode> {
    if kinds.contains(&current.kind) {
        return Some(current);
    }
    ancestors.iter().rev().find(|&&n| kinds.contains(&n.kind)).copied()
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Convert a raw byte-offset match into a [`ScanMatch`] and append it to `out`.
fn emit_match(
    source: &str,
    path: &Path,
    abs: usize,
    len: usize,
    context: MatchContext,
    rule: &Rule,
    scope_path: &[String],
    out: &mut Vec<ScanMatch>,
) {
    let (line, col) = byte_to_line_col(source, abs);
    out.push(ScanMatch {
        rule_name: rule.name.clone(),
        file: path.to_path_buf(),
        line,
        column: col,
        scope_path: scope_path.to_vec(),
        matched_text: source[abs..abs + len].to_string(),
        snippet: extract_snippet(source, abs, len),
        message: rule.message.clone(),
        severity: rule.severity.clone(),
        context,
        ai_verdict: None,
    });
}

/// Extract the source lines that the match spans, whitespace-trimmed.
///
/// For single-line matches this returns the one line containing `byte_pos`
/// (same behaviour as before).  For multiline matches every spanned line is
/// included, joined by `\n`, so callers see the full matched context.
///
/// If the resulting snippet exceeds 2 KB (e.g. a minified JS file with no
/// newlines), it is trimmed to a window around the match with ellipsis markers
/// so the output stays manageable.
fn extract_snippet(source: &str, byte_pos: usize, match_len: usize) -> String {
    const MAX_SNIPPET_BYTES: usize = 2048;
    const CONTEXT_BEFORE: usize = 120;
    const CONTEXT_AFTER: usize = 120;

    let match_end = (byte_pos + match_len).min(source.len());
    let start = source[..byte_pos].rfind('\n').map_or(0, |i| i + 1);
    let end   = source[match_end..].find('\n')
        .map_or(source.len(), |i| match_end + i);
    let raw = source[start..end].trim();

    if raw.len() <= MAX_SNIPPET_BYTES {
        return raw.to_string();
    }

    // Trim adjustments: raw starts at the first non-whitespace byte of the line.
    let leading_ws = source[start..end].len() - source[start..end].trim_start().len();
    let rel_start = byte_pos.saturating_sub(start + leading_ws);
    let rel_end   = match_end.saturating_sub(start + leading_ws).min(raw.len());

    let win_start = rel_start.saturating_sub(CONTEXT_BEFORE);
    // Snap to a valid UTF-8 boundary.
    let win_start = (0..=win_start).rev().find(|&i| raw.is_char_boundary(i)).unwrap_or(0);

    let win_end_raw = (rel_end + CONTEXT_AFTER).min(raw.len());
    let win_end = (win_end_raw..=raw.len()).find(|&i| raw.is_char_boundary(i)).unwrap_or(raw.len());

    let prefix = if win_start > 0 { "…" } else { "" };
    let suffix = if win_end < raw.len() { "…" } else { "" };
    format!("{}{}{}", prefix, &raw[win_start..win_end], suffix)
}

/// Determine whether byte `pos` falls inside a comment, a string literal, or plain code.
/// Comments take priority over strings (they cannot overlap, but this makes the intent explicit).
fn classify_position(
    pos: usize,
    comment_ranges: &[Range<usize>],
    string_ranges: &[Range<usize>],
) -> MatchContext {
    if in_any_range(pos, comment_ranges) {
        MatchContext::Comment
    } else if in_any_range(pos, string_ranges) {
        MatchContext::StringLiteral
    } else {
        MatchContext::Code
    }
}

/// Advance `pos` forward by at most `n` newlines, stopping at `limit`.
/// Returns the byte offset just after the n-th newline (or `limit` if fewer exist).
fn advance_n_lines(source: &[u8], pos: usize, n: usize, limit: usize) -> usize {
    let mut p = pos;
    let mut remaining = n;
    while p < limit {
        if source[p] == b'\n' {
            remaining -= 1;
            if remaining == 0 { return p + 1; }
        }
        p += 1;
    }
    limit
}

/// Retreat `pos` backward by at most `n` newlines, stopping at `floor`.
/// Returns the byte offset of the start of the line that is `n` newlines before `pos`.
fn retreat_n_lines(source: &[u8], pos: usize, n: usize, floor: usize) -> usize {
    if pos <= floor { return floor; }
    let mut p = pos - 1;
    let mut remaining = n;
    loop {
        if source[p] == b'\n' {
            if remaining == 0 { return p + 1; }
            remaining -= 1;
        }
        if p == floor { return floor; }
        p -= 1;
    }
}

/// Binary-search `ranges` (which must be sorted and non-overlapping) to check whether
/// `pos` falls inside any of them.
fn in_any_range(pos: usize, ranges: &[Range<usize>]) -> bool {
    let idx = ranges.partition_point(|r| r.start <= pos);
    idx > 0 && ranges[idx - 1].contains(&pos)
}

/// Iterate over the sub-ranges of `ranges` that overlap `body`, clipped to `body`'s bounds.
///
/// Uses a binary search to skip ranges that end before `body.start`, then stops as soon
/// as a range starts at or beyond `body.end`.  Each yielded range is clipped so callers
/// can use it directly as a slice index into the source without bounds-checking.
fn ranges_overlapping<'a>(
    ranges: &'a [Range<usize>],
    body: &'a Range<usize>,
) -> impl Iterator<Item = Range<usize>> + 'a {
    let start_idx = ranges.partition_point(|r| r.end <= body.start);
    ranges[start_idx..].iter().take_while(move |r| r.start < body.end).map(move |r| {
        r.start.max(body.start)..r.end.min(body.end)
    })
}

/// Compute the byte ranges within `body` that contain neither comments nor string literals.
///
/// These are the "code-only" intervals used by `SearchTarget::Code`.  The algorithm:
/// 1. Collect all comment and string ranges that overlap `body`.
/// 2. Sort and merge them into non-overlapping excluded intervals.
/// 3. Return the complement intervals inside `body`.
fn code_gaps(
    body: &Range<usize>,
    comment_ranges: &[Range<usize>],
    string_ranges: &[Range<usize>],
) -> Vec<Range<usize>> {
    let mut excluded: Vec<Range<usize>> = ranges_overlapping(comment_ranges, body)
        .chain(ranges_overlapping(string_ranges, body))
        .collect();

    excluded.sort_unstable_by_key(|r| r.start);
    let mut merged: Vec<Range<usize>> = Vec::new();
    for r in excluded {
        match merged.last_mut() {
            Some(last) if r.start <= last.end => last.end = last.end.max(r.end),
            _ => merged.push(r),
        }
    }

    let mut gaps = Vec::new();
    let mut cursor = body.start;
    for excl in &merged {
        if cursor < excl.start { gaps.push(cursor..excl.start); }
        cursor = excl.end;
    }
    if cursor < body.end { gaps.push(cursor..body.end); }
    gaps
}

/// Convert a byte offset into a 1-based `(line, column)` pair by counting newlines
/// in the prefix.  Column is byte-based (not Unicode codepoint-based).
fn byte_to_line_col(source: &str, byte_offset: usize) -> (usize, usize) {
    let prefix = &source[..byte_offset.min(source.len())];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = match prefix.rfind('\n') {
        Some(nl) => byte_offset - nl - 1,
        None     => byte_offset,
    } + 1;
    (line, col)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Lexer;
    use crate::rules::{ChainedPattern, ChainRelationship, Rule, ScopeFilter, SearchTarget, Severity};
    use crate::scope::ScopeParser;
    use grep::regex::RegexMatcherBuilder;

    // -----------------------------------------------------------------------
    // Source generator
    // -----------------------------------------------------------------------

    const PREAMBLE: &str = "class TestClass {\npublic:\n    void big_method() {\n";
    const POSTAMBLE: &str = "    }\n};\n";
    const PREAMBLE_LINES: usize = 3;

    fn lcg(s: u64) -> u64 {
        s.wrapping_mul(6364136223846793005)
         .wrapping_add(1442695040888963407)
    }

    fn build_large_source(
        target_body_bytes: usize,
        code_needle: &str,
        comment_needle: &str,
        code_every: usize,
        comment_every: usize,
    ) -> (String, Vec<usize>, Vec<usize>) {
        const FILLER: &[&str] = &[
            "alpha", "beta", "gamma", "delta", "epsilon",
            "zeta", "eta", "theta", "iota", "kappa",
        ];

        let mut body = String::with_capacity(target_body_bytes + 1024);
        let mut code_lines: Vec<usize> = Vec::new();
        let mut comment_lines: Vec<usize> = Vec::new();
        let mut rng: u64 = 0xdeadbeef_cafebabe;
        let mut body_line = 0usize;

        while body.len() < target_body_bytes {
            body_line += 1;
            let src_line = PREAMBLE_LINES + body_line;

            if body_line % code_every == 0 {
                body.push_str("        ");
                body.push_str(code_needle);
                body.push_str("();\n");
                code_lines.push(src_line);
            } else if body_line % comment_every == 0 {
                body.push_str("        // ");
                body.push_str(comment_needle);
                body.push('\n');
                comment_lines.push(src_line);
            } else {
                rng = lcg(rng);
                let w1 = FILLER[(rng >> 33) as usize % FILLER.len()];
                rng = lcg(rng);
                let w2 = FILLER[(rng >> 33) as usize % FILLER.len()];
                rng = lcg(rng);
                let w3 = FILLER[(rng >> 33) as usize % FILLER.len()];
                body.push_str(&format!("        {} = {} + {};\n", w1, w2, w3));
            }
        }

        (format!("{}{}{}", PREAMBLE, body, POSTAMBLE), code_lines, comment_lines)
    }

    fn make_rule(pattern: &str, filter: &str, target: SearchTarget) -> Rule {
        Rule {
            name: "test".to_string(),
            matcher: RegexMatcherBuilder::new().build(pattern).unwrap(),
            scope_filter: Some(ScopeFilter::parse(filter)),
            message: "test".to_string(),
            severity: Severity::Warning,
            search_target: target,
            chain: vec![],
        }
    }

    fn make_chained_rule(
        trigger: &str,
        filter: &str,
        chain: Vec<(&str, ChainRelationship)>,
    ) -> Rule {
        let chained = chain.into_iter().map(|(pat, rel)| ChainedPattern {
            matcher: RegexMatcherBuilder::new().build(pat).unwrap(),
            relationship: rel,
            negate: false,
            within_lines: None,
        }).collect();
        Rule {
            name: "chain_test".to_string(),
            matcher: RegexMatcherBuilder::new().build(trigger).unwrap(),
            scope_filter: Some(ScopeFilter::parse(filter)),
            message: "chain".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: chained,
        }
    }

    fn run(source: &str, rules: &[Rule]) -> Vec<ScanMatch> {
        let lex  = Lexer::new(source).tokenize();
        let tree = ScopeParser::new(crate::scope::profile_for_ext("cpp")).parse(&lex.tokens, source.len());
        scan_file(source, Path::new("test.cpp"), &tree, rules, &lex)
    }

    fn run_single(source: &str, filter: &str, needle: &str) -> Vec<ScanMatch> {
        run(source, &[make_rule(needle, filter, SearchTarget::All)])
    }

    /// Variant of `make_chained_rule` that accepts a `negate` flag per chain entry.
    fn make_chained_rule_neg(
        trigger: &str,
        filter: &str,
        chain: Vec<(&str, ChainRelationship, bool)>,
    ) -> Rule {
        let chained = chain.into_iter().map(|(pat, rel, neg)| ChainedPattern {
            matcher: RegexMatcherBuilder::new().build(pat).unwrap(),
            relationship: rel,
            negate: neg,
            within_lines: None,
        }).collect();
        Rule {
            name: "chain_neg_test".to_string(),
            matcher: RegexMatcherBuilder::new().build(trigger).unwrap(),
            scope_filter: Some(ScopeFilter::parse(filter)),
            message: "chain_neg".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: chained,
        }
    }

    /// Like `run` but uses the profile for `ext` instead of C++.
    fn run_for_lang(source: &str, rules: &[Rule], ext: &str) -> Vec<ScanMatch> {
        let lex  = Lexer::new(source).tokenize();
        let tree = ScopeParser::new(crate::scope::profile_for_ext(ext)).parse(&lex.tokens, source.len());
        scan_file(source, Path::new(&format!("test.{ext}")), &tree, rules, &lex)
    }

    fn run_single_lang(source: &str, filter: &str, needle: &str, ext: &str) -> Vec<ScanMatch> {
        run_for_lang(source, &[make_rule(needle, filter, SearchTarget::All)], ext)
    }

    // -----------------------------------------------------------------------
    // UTF-8 BOM resilience
    // -----------------------------------------------------------------------

    // Files produced by MSVC often begin with a UTF-8 BOM (U+FEFF, bytes EF BB BF).
    // The virtual File root scope uses body_start=0, so body_range() used to return
    // 1..len, causing source[1..] to panic when byte 1 is inside the 3-byte BOM.
    // Verify that scanning such files with scope="**" (which hits the root scope) and
    // SearchTarget::Code does not panic and correctly finds matches.

    #[test]
    fn bom_file_code_search_does_not_panic() {
        // BOM at byte 0, then a global-scope needle (no enclosing class/function).
        let source = "\u{FEFF}// top of file\nstrcpy(dst, src);\n";
        let rule = make_rule("strcpy", "**", SearchTarget::Code);
        let matches = run(source, &[rule]);
        assert_eq!(matches.len(), 1, "expected one match in BOM file");
        assert_eq!(matches[0].matched_text, "strcpy");
    }

    #[test]
    fn bom_file_all_search_does_not_panic() {
        // Same source, SearchTarget::All – exercises the body[0..] slice on the root.
        let source = "\u{FEFF}strcpy(dst, src); // bad\n";
        let rule = make_rule("strcpy", "**", SearchTarget::All);
        let matches = run(source, &[rule]);
        assert_eq!(matches.len(), 1);
    }

    #[test]
    fn bom_file_match_inside_class() {
        // BOM + normal class body – confirms named scopes still work correctly.
        let source = "\u{FEFF}class Foo {\n    void bar() { strcpy(d, s); }\n};\n";
        let rule = make_rule("strcpy", "Foo::bar", SearchTarget::Code);
        let matches = run(source, &[rule]);
        assert_eq!(matches.len(), 1);
        assert_eq!(matches[0].scope_path, vec!["Foo", "bar"]);
    }

    // -----------------------------------------------------------------------
    // Large-file tests
    // -----------------------------------------------------------------------

    #[test]
    fn large_body_code_needles_found_at_correct_lines() {
        let (source, code_lines, _) = build_large_source(
            128 * 1024, "CODE_NEEDLE", "COMMENT_NEEDLE", 97, 53,
        );
        let rule = make_rule("CODE_NEEDLE", "TestClass::big_method", SearchTarget::All);
        let matches = run(&source, &[rule]);

        assert_eq!(matches.len(), code_lines.len(),
            "expected {} code matches, got {}", code_lines.len(), matches.len());
        for (m, &expected_line) in matches.iter().zip(code_lines.iter()) {
            assert_eq!(m.line, expected_line,
                "wrong line: expected {expected_line}, got {}", m.line);
            assert_eq!(m.scope_path, vec!["TestClass", "big_method"]);
            assert_eq!(m.context, MatchContext::Code);
        }
    }

    #[test]
    fn large_body_comment_needles_annotated_as_comment() {
        let (source, _, comment_lines) = build_large_source(
            128 * 1024, "CODE_NEEDLE", "COMMENT_NEEDLE", 97, 53,
        );
        let rule = make_rule("COMMENT_NEEDLE", "TestClass::big_method", SearchTarget::All);
        let matches = run(&source, &[rule]);

        assert_eq!(matches.len(), comment_lines.len());
        for (m, &expected_line) in matches.iter().zip(comment_lines.iter()) {
            assert_eq!(m.line, expected_line);
            assert_eq!(m.context, MatchContext::Comment);
        }
    }

    #[test]
    fn large_body_comment_search_excludes_code_matches() {
        let (source, _, comment_lines) = build_large_source(
            128 * 1024, "SHARED_NEEDLE", "SHARED_NEEDLE", 150, 97,
        );
        let rule = make_rule("SHARED_NEEDLE", "TestClass::big_method", SearchTarget::Comments);
        let matches = run(&source, &[rule]);

        assert_eq!(matches.len(), comment_lines.len(),
            "comment-only search: expected {} matches, got {}",
            comment_lines.len(), matches.len());
        for m in &matches { assert_eq!(m.context, MatchContext::Comment); }
        for (m, &expected_line) in matches.iter().zip(comment_lines.iter()) {
            assert_eq!(m.line, expected_line);
        }
    }

    // -----------------------------------------------------------------------
    // Nesting-depth helpers + tests
    // -----------------------------------------------------------------------

    fn build_deeply_nested(ns_depth: usize, class_depth: usize, needle: &str) -> (String, Vec<String>) {
        let mut src  = String::new();
        let mut path = Vec::new();
        for i in 0..ns_depth {
            let name = format!("ns{i}");
            src.push_str(&format!("namespace {name} {{\n"));
            path.push(name);
        }
        for i in 0..class_depth {
            let name = format!("Class{i}");
            src.push_str(&format!("class {name} {{\npublic:\n"));
            path.push(name);
        }
        src.push_str("    void leaf_fn() {\n");
        path.push("leaf_fn".to_string());
        src.push_str(&format!("        {needle}();\n"));
        src.push_str("    }\n");
        for _ in 0..class_depth { src.push_str("};\n"); }
        for _ in 0..ns_depth    { src.push_str("}\n"); }
        (src, path)
    }

    #[test]
    fn deep_namespace_nesting_correct_path() {
        let (src, expected_path) = build_deeply_nested(20, 1, "DEEP_NEEDLE");
        let ms = run_single(&src, "**::leaf_fn", "DEEP_NEEDLE");
        assert_eq!(ms.len(), 1, "expected exactly one match in the leaf method");
        assert_eq!(ms[0].scope_path, expected_path, "scope path mismatch at depth 20");
        assert_eq!(ms[0].context, MatchContext::Code);
    }

    #[test]
    fn deep_class_nesting_correct_path() {
        let (src, expected_path) = build_deeply_nested(0, 6, "DEEP_NEEDLE");
        let ms = run_single(&src, "**::leaf_fn", "DEEP_NEEDLE");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, expected_path, "scope path mismatch at class depth 6");
    }

    #[test]
    fn mixed_namespace_and_class_nesting_correct_path() {
        let (src, expected_path) = build_deeply_nested(10, 4, "DEEP_NEEDLE");
        let ms = run_single(&src, "**::leaf_fn", "DEEP_NEEDLE");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, expected_path);
    }

    // -----------------------------------------------------------------------
    // Delimiter-interference tests
    // -----------------------------------------------------------------------

    #[test]
    fn braces_inside_string_literals_dont_affect_scope() {
        let src = r#"
class Widget {
public:
    void tricky() {
        const char* s1 = "namespace Fake { class Impostor { void bad() {";
        const char* s2 = "} } } closing braces that would close Widget";
        const char* s3 = "char c = '{'; more = '}';";
        char brace_open  = '{';
        char brace_close = '}';
        NEEDLE_A();
    }

    void clean() {
        NEEDLE_B();
    }
};
"#;
        let rule_a = make_rule("NEEDLE_A", "Widget::tricky", SearchTarget::All);
        let rule_b = make_rule("NEEDLE_B", "Widget::clean",  SearchTarget::All);
        let ms = run(src, &[rule_a, rule_b]);

        assert_eq!(ms.len(), 2, "expected both methods to be found");
        assert_eq!(ms[0].scope_path, vec!["Widget", "tricky"]);
        assert_eq!(ms[0].context, MatchContext::Code);
        assert_eq!(ms[1].scope_path, vec!["Widget", "clean"]);
        assert_eq!(ms[1].context, MatchContext::Code);
    }

    #[test]
    fn braces_inside_comments_dont_affect_scope() {
        let src = r#"
namespace NS {
class Safe {
public:
    void method() {
        // { { { fake opens  — namespace Ghost { class Phantom {
        /* closing: } } }
           more opens: { { {
           method() } end */
        // if (x) { for (;;) { while (1) {
        NEEDLE_A();
    }

    // } this closing brace is in a comment and must not close Safe
    void also_fine() {
        NEEDLE_B();
    }
};
}
"#;
        let rule_a = make_rule("NEEDLE_A", "NS::Safe::method",    SearchTarget::All);
        let rule_b = make_rule("NEEDLE_B", "NS::Safe::also_fine", SearchTarget::All);
        let ms = run(src, &[rule_a, rule_b]);

        assert_eq!(ms.len(), 2, "both methods must be reachable");
        assert_eq!(ms[0].scope_path, vec!["NS", "Safe", "method"]);
        assert_eq!(ms[1].scope_path, vec!["NS", "Safe", "also_fine"]);
    }

    #[test]
    fn deeply_nested_parens_in_function_signature() {
        let src = r#"
namespace NS {
class Widget {
public:
    void process(
        std::function<void(std::function<int(int, std::string)>)> cb,
        std::map<std::string, std::vector<std::pair<int, int>>>   data,
        int (*raw_fp)(int (*)(int))
    ) {
        NEEDLE();
    }
};
}
"#;
        let ms = run_single(src, "NS::Widget::process", "NEEDLE");
        assert_eq!(ms.len(), 1, "method with deeply nested signature must be found");
        assert_eq!(ms[0].scope_path, vec!["NS", "Widget", "process"]);
    }

    #[test]
    fn combined_delimiter_chaos() {
        let src = r#"
namespace Outer {
class C1 {
public:
    // { looks like scope open; so does the next comment: namespace Fake {
    /* and this one closes nothing: } } }
       multi-line block with { { { many } } } braces } */
    void chaos(
        std::function<void(std::function<int(int)>)> cb
    ) {
        // { more fake opens } and (fake parens (nested (deeply)))
        std::string s = "} } } { class Fake { void impostor() { } } }";
        char brace_open  = '{';
        char brace_close = '}';
        char paren_open  = '(';
        char paren_close = ')';
        /* block: { { ( ) } } */
        NEEDLE_A();
    }

    void after_chaos() {
        NEEDLE_B();
    }
};
}
"#;
        let rule_a = make_rule("NEEDLE_A", "Outer::C1::chaos",       SearchTarget::All);
        let rule_b = make_rule("NEEDLE_B", "Outer::C1::after_chaos", SearchTarget::All);
        let ms = run(src, &[rule_a, rule_b]);

        assert_eq!(ms.len(), 2, "both methods must survive the delimiter chaos");
        assert_eq!(ms[0].scope_path, vec!["Outer", "C1", "chaos"]);
        assert_eq!(ms[0].context, MatchContext::Code);
        assert_eq!(ms[1].scope_path, vec!["Outer", "C1", "after_chaos"]);
        assert_eq!(ms[1].context, MatchContext::Code);
    }

    // -----------------------------------------------------------------------
    // Chain tests
    // -----------------------------------------------------------------------

    /// Trigger A must be followed by B in the same method → one match.
    #[test]
    fn chain_after_fires_when_both_present() {
        let src = "class C { public: void f() { foo(); bar(); } };\n";
        let rule = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::After)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].matched_text, "foo");
    }

    /// A is present but B does not follow → no match.
    #[test]
    fn chain_after_suppressed_when_consequent_absent() {
        let src = "class C { public: void f() { foo(); baz(); } };\n";
        let rule = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::After)]);
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// B appears before A (wrong order) → `after` chain not satisfied.
    #[test]
    fn chain_after_suppressed_when_consequent_only_before() {
        let src = "class C { public: void f() { bar(); foo(); } };\n";
        let rule = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::After)]);
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// `before` relationship: B must appear before A.
    #[test]
    fn chain_before_fires_when_antecedent_present() {
        let src = "class C { public: void f() { bar(); foo(); } };\n";
        let rule = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::Before)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
    }

    /// `before` suppressed when antecedent appears only after.
    #[test]
    fn chain_before_suppressed_when_antecedent_only_after() {
        let src = "class C { public: void f() { foo(); bar(); } };\n";
        let rule = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::Before)]);
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// `anywhere_in_method` fires regardless of order.
    #[test]
    fn chain_anywhere_in_method_ignores_order() {
        // bar after foo
        let src1 = "class C { public: void f() { foo(); bar(); } };\n";
        // bar before foo
        let src2 = "class C { public: void f() { bar(); foo(); } };\n";

        let rule1 = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::AnywhereInMethod)]);
        let rule2 = make_chained_rule("foo", "C::f", vec![("bar", ChainRelationship::AnywhereInMethod)]);

        assert_eq!(run(src1, &[rule1]).len(), 1);
        assert_eq!(run(src2, &[rule2]).len(), 1);
    }

    /// `anywhere_in_class`: trigger in method1, chain in method2 → match.
    #[test]
    fn chain_anywhere_in_class_crosses_methods() {
        let src = r#"
class MyClass {
public:
    void method1() { foo(); }
    void method2() { bar(); }
};
"#;
        let rule = make_chained_rule("foo", "MyClass::method1",
            vec![("bar", ChainRelationship::AnywhereInClass)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1, "should find foo because bar exists elsewhere in class");
    }

    /// `anywhere_in_class` suppressed when chain pattern is absent from class.
    #[test]
    fn chain_anywhere_in_class_suppressed_when_absent() {
        let src = r#"
class MyClass {
public:
    void method1() { foo(); }
    void method2() { baz(); }
};
"#;
        let rule = make_chained_rule("foo", "MyClass::method1",
            vec![("bar", ChainRelationship::AnywhereInClass)]);
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// `anywhere_in_namespace`: trigger in Class1, chain in Class2 → match.
    #[test]
    fn chain_anywhere_in_namespace_crosses_classes() {
        let src = r#"
namespace NS {
class Class1 { public: void f() { foo(); } };
class Class2 { public: void g() { bar(); } };
}
"#;
        let rule = make_chained_rule("foo", "NS::Class1::f",
            vec![("bar", ChainRelationship::AnywhereInNamespace)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1, "should match because bar exists in the same namespace");
    }

    /// `anywhere_in_namespace` suppressed when chain absent from namespace.
    #[test]
    fn chain_anywhere_in_namespace_suppressed_when_absent() {
        let src = r#"
namespace NS {
class Class1 { public: void f() { foo(); } };
class Class2 { public: void g() { baz(); } };
}
"#;
        let rule = make_chained_rule("foo", "NS::Class1::f",
            vec![("bar", ChainRelationship::AnywhereInNamespace)]);
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// Multiple chain conditions: ALL must be satisfied.
    #[test]
    fn chain_multi_condition_all_required() {
        let src_all = "class C { public: void f() { foo(); step1(); step2(); } };\n";
        let src_missing_step2 = "class C { public: void f() { foo(); step1(); } };\n";

        let rule_all = make_chained_rule("foo", "C::f", vec![
            ("step1", ChainRelationship::After),
            ("step2", ChainRelationship::After),
        ]);
        let rule_missing = make_chained_rule("foo", "C::f", vec![
            ("step1", ChainRelationship::After),
            ("step2", ChainRelationship::After),
        ]);

        assert_eq!(run(src_all,          &[rule_all]).len(),     1, "all conditions present → match");
        assert_eq!(run(src_missing_step2, &[rule_missing]).len(), 0, "missing step2 → no match");
    }

    // -----------------------------------------------------------------------
    // Negated chain tests
    // -----------------------------------------------------------------------

    /// negate=true fires when the chain pattern is *absent* from the search range.
    #[test]
    fn chain_negate_fires_when_pattern_absent() {
        let src = "class C { public: void f() { foo(); } };\n";
        let rule = make_chained_rule_neg("foo", "C::f",
            vec![("bar", ChainRelationship::AnywhereInMethod, true)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1, "negate chain should fire when pattern is absent");
    }

    /// negate=true is suppressed when the chain pattern *is* present.
    #[test]
    fn chain_negate_suppressed_when_pattern_present() {
        let src = "class C { public: void f() { foo(); bar(); } };\n";
        let rule = make_chained_rule_neg("foo", "C::f",
            vec![("bar", ChainRelationship::AnywhereInMethod, true)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 0, "negate chain should be suppressed when pattern is present");
    }

    /// negate=true with anywhere_in_class: fires when the pattern is absent from the
    /// entire class body (not just the current method).
    #[test]
    fn chain_negate_anywhere_in_class_fires_when_absent() {
        let src = r#"
class MyClass {
public:
    void method1() { trigger(); }
    void method2() { unrelated(); }
};
"#;
        let rule = make_chained_rule_neg("trigger", "MyClass::method1",
            vec![("guard_call", ChainRelationship::AnywhereInClass, true)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1, "guard absent from whole class → should fire");
    }

    /// negate=true with anywhere_in_class: suppressed when pattern appears in a
    /// *different* method of the same class.
    #[test]
    fn chain_negate_anywhere_in_class_suppressed_by_other_method() {
        let src = r#"
class MyClass {
public:
    void method1() { trigger(); }
    void method2() { guard_call(); }
};
"#;
        let rule = make_chained_rule_neg("trigger", "MyClass::method1",
            vec![("guard_call", ChainRelationship::AnywhereInClass, true)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 0, "guard present elsewhere in class → should suppress");
    }

    // -----------------------------------------------------------------------
    // AnywhereInStatement tests
    // -----------------------------------------------------------------------

    /// Chain pattern present in the same statement as the trigger → fires.
    #[test]
    fn anywhere_in_statement_fires_when_pattern_in_same_statement() {
        // Both TRIGGER and GUARD are inside the same UFUNCTION()-style declaration,
        // before the first semicolon.
        let src = "class C {\n    UFUNCTION(TRIGGER, GUARD)\n    void Rpc();\n};\n";
        let rule = make_chained_rule("TRIGGER", "**",
            vec![("GUARD", ChainRelationship::AnywhereInStatement)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
    }

    /// Chain pattern is in a *different* statement — must not fire.
    #[test]
    fn anywhere_in_statement_isolated_to_current_statement() {
        // GUARD appears only in the second declaration, not the first.
        let src = "class C {\n    UFUNCTION(TRIGGER)\n    void RpcA();\n    UFUNCTION(GUARD)\n    void RpcB();\n};\n";
        let rule = make_chained_rule("TRIGGER", "**",
            vec![("GUARD", ChainRelationship::AnywhereInStatement)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 0, "GUARD in a different statement must not satisfy the chain");
    }

    /// Simulates the UE5 Server RPC use-case: per-declaration WithValidation detection.
    /// The first RPC has no WithValidation → negate chain fires.
    /// The second RPC has WithValidation → negate chain is suppressed.
    #[test]
    fn anywhere_in_statement_negate_per_declaration_ue5_style() {
        let src = concat!(
            "class AMyActor {\npublic:\n",
            "    UFUNCTION(Server, Reliable)\n",
            "    void RpcNoValidation(float Value);\n",
            "    UFUNCTION(Server, Reliable, WithValidation)\n",
            "    void RpcWithValidation(float Value);\n",
            "};\n",
        );
        let rule = make_chained_rule_neg("Server", "**",
            vec![("WithValidation", ChainRelationship::AnywhereInStatement, true)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1, "only the RPC without WithValidation should fire");
        assert!(ms[0].matched_text == "Server");
        // Verify it matched in the first declaration (line 3), not the second (line 5)
        assert_eq!(ms[0].line, 3);
    }

    /// A brace boundary (method body open) also terminates the statement window.
    #[test]
    fn anywhere_in_statement_stops_at_brace() {
        // GUARD is inside the function body (after `{`), not in the same statement
        // as the TRIGGER in the signature.
        let src = "class C {\npublic:\n    void Method(TRIGGER arg) {\n        GUARD();\n    }\n};\n";
        let rule = make_chained_rule("TRIGGER", "**",
            vec![("GUARD", ChainRelationship::AnywhereInStatement)]);
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 0, "GUARD inside the body brace is outside the statement window");
    }

    // -----------------------------------------------------------------------
    // Go
    // -----------------------------------------------------------------------

    /// Plain top-level function: `func Name(args) { }` → Function("Name").
    #[test]
    fn go_named_function_correct_scope_path() {
        let src = "package main\n\nfunc Greet(name string) {\n    NEEDLE()\n}\n";
        let ms = run_single_lang(src, "**::Greet", "NEEDLE", "go");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Greet"]);
    }

    /// Receiver method: `func (w *Widget) Render() { }` — receiver group skipped,
    /// name is the word after the closing `)`.
    #[test]
    fn go_receiver_method_name_resolved() {
        let src = "type Widget struct { X int }\n\nfunc (w *Widget) Render() {\n    NEEDLE()\n}\n";
        let ms = run_single_lang(src, "**::Render", "NEEDLE", "go");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Render"]);
    }

    /// `type Config struct { }` — name precedes the keyword; look-back heuristic
    /// must resolve the struct name to "Config" so the scope filter can match it.
    #[test]
    fn go_struct_name_before_keyword_resolved() {
        let src = "type Config struct {\n    NEEDLE_FIELD string\n}\n";
        let ms = run_single_lang(src, "**::Config", "NEEDLE_FIELD", "go");
        assert_eq!(ms.len(), 1, "struct should be named Config via look-back heuristic");
        assert_eq!(ms[0].scope_path, vec!["Config"]);
    }

    /// Same look-back for interfaces: `type Reader interface { }`.
    #[test]
    fn go_interface_name_before_keyword_resolved() {
        let src = "type Reader interface {\n    NEEDLE_METHOD() []byte\n}\n";
        let ms = run_single_lang(src, "**::Reader", "NEEDLE_METHOD", "go");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Reader"]);
    }

    /// Backtick raw strings may contain `{` and `}` — without lexer support these
    /// would push/pop phantom scope frames and corrupt the parser state.
    #[test]
    fn go_backtick_raw_string_doesnt_corrupt_scope() {
        let src = "package main\n\nfunc outer() {\n    q := `SELECT * FROM t WHERE id > 0 AND { x = 1 }`\n    NEEDLE()\n}\n\nfunc after() {\n    NEEDLE_B()\n}\n";
        let rule_a = make_rule("NEEDLE",   "**::outer", SearchTarget::All);
        let rule_b = make_rule("NEEDLE_B", "**::after", SearchTarget::All);
        let ms = run_for_lang(src, &[rule_a, rule_b], "go");
        assert_eq!(ms.len(), 2, "backtick brace must not corrupt parser state");
        assert_eq!(ms[0].scope_path, vec!["outer"]);
        assert_eq!(ms[1].scope_path, vec!["after"]);
    }

    // -----------------------------------------------------------------------
    // Rust
    // -----------------------------------------------------------------------

    /// `mod` maps to Namespace; `fn` introduces functions.
    #[test]
    fn rust_mod_and_fn() {
        let src = "mod mymod {\n    fn helper() {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "mymod::helper", "NEEDLE", "rs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["mymod", "helper"]);
    }

    /// `impl` maps to Class; method inside uses `fn`.
    #[test]
    fn rust_impl_and_fn() {
        let src = "struct Counter { value: i32 }\n\nimpl Counter {\n    fn increment(&mut self) {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Counter::increment", "NEEDLE", "rs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Counter", "increment"]);
    }

    /// `trait` maps to Interface; default method body is scannable.
    #[test]
    fn rust_trait_default_method() {
        let src = "trait Drawable {\n    fn draw(&self) {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Drawable::draw", "NEEDLE", "rs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Drawable", "draw"]);
    }

    /// Nested `mod` blocks produce deep scope paths.
    #[test]
    fn rust_nested_mods() {
        let src = "mod outer {\n    mod inner {\n        fn leaf() {\n            NEEDLE()\n        }\n    }\n}\n";
        let ms = run_single_lang(src, "outer::inner::leaf", "NEEDLE", "rs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["outer", "inner", "leaf"]);
    }

    // -----------------------------------------------------------------------
    // Swift
    // -----------------------------------------------------------------------

    #[test]
    fn swift_class_and_func() {
        let src = "class Vehicle {\n    func start() {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Vehicle::start", "NEEDLE", "swift");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Vehicle", "start"]);
    }

    #[test]
    fn swift_struct_and_func() {
        let src = "struct Point {\n    func distance() -> Double {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Point::distance", "NEEDLE", "swift");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Point", "distance"]);
    }

    /// `protocol` maps to Interface.
    #[test]
    fn swift_protocol_and_func() {
        let src = "protocol Drawable {\n    func draw() {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Drawable::draw", "NEEDLE", "swift");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Drawable", "draw"]);
    }

    /// `extension` maps to Class — lets rules target retroactively-added methods.
    #[test]
    fn swift_extension_and_func() {
        let src = "extension String {\n    func shout() -> String {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "String::shout", "NEEDLE", "swift");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["String", "shout"]);
    }

    // -----------------------------------------------------------------------
    // Kotlin
    // -----------------------------------------------------------------------

    #[test]
    fn kotlin_class_and_fun() {
        let src = "class Calculator {\n    fun add(a: Int, b: Int): Int {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Calculator::add", "NEEDLE", "kt");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Calculator", "add"]);
    }

    /// `object` declarations are singleton classes in Kotlin.
    #[test]
    fn kotlin_object_declaration() {
        let src = "object Logger {\n    fun log(msg: String) {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Logger::log", "NEEDLE", "kt");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Logger", "log"]);
    }

    #[test]
    fn kotlin_interface_default_method() {
        let src = "interface Printable {\n    fun print() {\n        NEEDLE()\n    }\n}\n";
        let ms = run_single_lang(src, "Printable::print", "NEEDLE", "kt");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Printable", "print"]);
    }

    // -----------------------------------------------------------------------
    // Java
    // -----------------------------------------------------------------------

    /// Java has no brace-delimited namespace; classes are the outermost named scope.
    #[test]
    fn java_class_and_method() {
        let src = "public class Calculator {\n    public int add(int a, int b) {\n        NEEDLE();\n        return a + b;\n    }\n}\n";
        let ms = run_single_lang(src, "Calculator::add", "NEEDLE", "java");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Calculator", "add"]);
    }

    #[test]
    fn java_interface_default_method() {
        let src = "public interface Drawable {\n    default void draw() {\n        NEEDLE();\n    }\n}\n";
        let ms = run_single_lang(src, "Drawable::draw", "NEEDLE", "java");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Drawable", "draw"]);
    }

    /// Enum with a method body — the semicolon after the constants clears the header
    /// so the method declaration is classified normally.
    #[test]
    fn java_enum_with_method() {
        let src = "public enum Status {\n    ACTIVE, INACTIVE;\n    public String display() {\n        NEEDLE();\n        return name();\n    }\n}\n";
        let ms = run_single_lang(src, "Status::display", "NEEDLE", "java");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Status", "display"]);
    }

    #[test]
    fn java_nested_classes() {
        let src = "public class Outer {\n    public class Inner {\n        public void method() {\n            NEEDLE();\n        }\n    }\n}\n";
        let ms = run_single_lang(src, "Outer::Inner::method", "NEEDLE", "java");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["Outer", "Inner", "method"]);
    }

    // -----------------------------------------------------------------------
    // C#
    // -----------------------------------------------------------------------

    /// C# keeps `namespace` as a brace scope, unlike Java.
    #[test]
    fn csharp_namespace_class_method() {
        let src = "namespace MyApp {\n    public class Service {\n        public void Execute() {\n            NEEDLE();\n        }\n    }\n}\n";
        let ms = run_single_lang(src, "MyApp::Service::Execute", "NEEDLE", "cs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["MyApp", "Service", "Execute"]);
    }

    /// C# 9+ `record` keyword maps to Class, so methods inside are reachable.
    #[test]
    fn csharp_record_method() {
        let src = "namespace MyApp {\n    public record Point(int X, int Y) {\n        public double Length() {\n            NEEDLE();\n            return 0.0;\n        }\n    }\n}\n";
        let ms = run_single_lang(src, "MyApp::Point::Length", "NEEDLE", "cs");
        assert_eq!(ms.len(), 1);
        assert_eq!(ms[0].scope_path, vec!["MyApp", "Point", "Length"]);
    }

    // -----------------------------------------------------------------------
    // Multiline regex
    // -----------------------------------------------------------------------

    /// Explicit `\n` in pattern matches a SQL-style query spanning two lines.
    /// This works without `multiline = true` because the scope body is searched
    /// as a single byte slice (no line terminator restriction in the grep crate).
    #[test]
    fn multiline_explicit_newline_fires() {
        // SELECT and FROM are on separate lines in actual code (not inside a string).
        let src = "class Dao {\n    void query() {\n        SELECT id,\n        FROM users;\n    }\n};\n";
        // Pattern with explicit \n — no dot_matches_new_line needed.
        let rule = Rule {
            name: "sql_select".to_string(),
            matcher: RegexMatcherBuilder::new()
                .build(r"\bSELECT\b[^\n]*\n[^\n]*\bFROM\b")
                .unwrap(),
            scope_filter: None,
            message: "raw SQL".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![],
        };
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
        assert!(ms[0].matched_text.contains("SELECT") && ms[0].matched_text.contains("FROM"),
            "matched_text should span both keywords: {:?}", ms[0].matched_text);
    }

    /// With `dot_matches_new_line = true` (enabled by `multiline = true` in TOML),
    /// a pattern using plain `.` can match across newlines.
    #[test]
    fn multiline_dot_matches_newline_fires() {
        let src = "class Dao {\n    void query() {\n        db.exec(SELECT_TOKEN);\n        // FROM_TOKEN referenced here\n    }\n};\n";
        let rule = Rule {
            name: "sql_dotall".to_string(),
            matcher: RegexMatcherBuilder::new()
                .multi_line(true)
                .dot_matches_new_line(true)
                .build(r"\bSELECT_TOKEN\b.+\bFROM_TOKEN\b")
                .unwrap(),
            scope_filter: None,
            message: "raw SQL".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![],
        };
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
        assert!(ms[0].matched_text.contains("SELECT_TOKEN") && ms[0].matched_text.contains("FROM_TOKEN"));
    }

    /// A multiline match's snippet covers all spanned lines.
    #[test]
    fn multiline_snippet_spans_matched_lines() {
        // Two-line match: SELECT on line 3, FROM on line 4.
        let src = "class Dao {\n    void query() {\n        SELECT id,\n        FROM users;\n    }\n};\n";
        let rule = Rule {
            name: "sql_select".to_string(),
            matcher: RegexMatcherBuilder::new()
                .multi_line(true)
                .dot_matches_new_line(true)
                .build(r"\bSELECT\b.+\bFROM\b")
                .unwrap(),
            scope_filter: None,
            message: "raw SQL".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![],
        };
        let ms = run(src, &[rule]);
        assert_eq!(ms.len(), 1);
        // Snippet must contain both lines.
        assert!(ms[0].snippet.contains("SELECT"), "snippet missing SELECT: {:?}", ms[0].snippet);
        assert!(ms[0].snippet.contains("FROM"),   "snippet missing FROM: {:?}", ms[0].snippet);
    }

    /// within_lines: chain fires when the companion pattern is within the line window.
    #[test]
    fn within_lines_fires_when_companion_close() {
        // WHERE appears 2 lines after SET — within_lines = 3 should fire.
        let src = "class Dao {\n    void q() {\n        UPDATE users\n        SET name = ?\n        WHERE id = ?;\n    }\n};\n";
        let rule = Rule {
            name: "upd".to_string(),
            matcher: RegexMatcherBuilder::new().build(r"\bUPDATE\b").unwrap(),
            scope_filter: None,
            message: "t".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![ChainedPattern {
                matcher: RegexMatcherBuilder::new().build(r"\bWHERE\b").unwrap(),
                relationship: ChainRelationship::After,
                negate: false,
                within_lines: Some(3),
            }],
        };
        assert_eq!(run(src, &[rule]).len(), 1);
    }

    /// within_lines: chain suppressed when companion is beyond the line window.
    #[test]
    fn within_lines_suppressed_when_companion_too_far() {
        // WHERE appears 6 lines after SET — within_lines = 3 should suppress.
        let src = "class Dao {\n    void q() {\n        UPDATE users\n        SET a = 1,\n        b = 2,\n        c = 3,\n        d = 4\n        WHERE id = ?;\n    }\n};\n";
        let rule = Rule {
            name: "upd".to_string(),
            matcher: RegexMatcherBuilder::new().build(r"\bUPDATE\b").unwrap(),
            scope_filter: None,
            message: "t".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![ChainedPattern {
                matcher: RegexMatcherBuilder::new().build(r"\bWHERE\b").unwrap(),
                relationship: ChainRelationship::After,
                negate: false,
                within_lines: Some(3),
            }],
        };
        assert_eq!(run(src, &[rule]).len(), 0);
    }

    /// within_lines: companion present but source ends before the window is exhausted.
    /// Must not panic or miss the match when fewer than N lines remain after the trigger.
    #[test]
    fn within_lines_fires_at_end_of_source() {
        // WHERE is 1 line after UPDATE but the file ends immediately after — within_lines=5.
        let src = "class Dao {\n    void q() {\n        UPDATE t SET x = 1\n        WHERE id = 1;\n    }\n};\n";
        let rule = Rule {
            name: "upd".to_string(),
            matcher: RegexMatcherBuilder::new().build(r"\bUPDATE\b").unwrap(),
            scope_filter: None,
            message: "t".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![ChainedPattern {
                matcher: RegexMatcherBuilder::new().build(r"\bWHERE\b").unwrap(),
                relationship: ChainRelationship::After,
                negate: false,
                within_lines: Some(5),  // more lines than exist after trigger
            }],
        };
        assert_eq!(run(src, &[rule]).len(), 1, "should fire even when window exceeds remaining source");
    }

    /// within_lines: negate fires when companion absent and window hits end of source.
    #[test]
    fn within_lines_negate_at_end_of_source() {
        let src = "class Dao {\n    void q() {\n        DELETE FROM t;\n    }\n};\n";
        let rule = Rule {
            name: "del".to_string(),
            matcher: RegexMatcherBuilder::new().build(r"\bDELETE\b").unwrap(),
            scope_filter: None,
            message: "t".to_string(),
            severity: Severity::Warning,
            search_target: SearchTarget::All,
            chain: vec![ChainedPattern {
                matcher: RegexMatcherBuilder::new().build(r"\bWHERE\b").unwrap(),
                relationship: ChainRelationship::After,
                negate: true,
                within_lines: Some(10),
            }],
        };
        assert_eq!(run(src, &[rule]).len(), 1, "negate should fire when WHERE absent within window");
    }

    /// A single-line match snippet is unchanged (regression guard).
    #[test]
    fn singleline_snippet_unchanged() {
        let src = "class Foo {\n    void bar() { NEEDLE(); }\n};\n";
        let ms = run_single(src, "Foo::bar", "NEEDLE");
        assert_eq!(ms.len(), 1);
        assert!(!ms[0].snippet.contains('\n'), "single-line snippet should have no newlines");
        assert!(ms[0].snippet.contains("NEEDLE"));
    }

    /// Snippets from huge single lines (e.g. minified JS) are trimmed to a
    /// window around the match and never exceed ~300 bytes.
    #[test]
    fn large_line_snippet_is_trimmed() {
        // Build a single massive line: 1500 chars of 'a', then NEEDLE, then 1500 chars of 'b'.
        // Wrap in a minimal class+method so the engine produces a match.
        let pad_a = "a".repeat(1500);
        let pad_b = "b".repeat(1500);
        let inner = format!("{pad_a}NEEDLE(){pad_b}");
        let src = format!("class F {{\n    void g() {{ {inner} }}\n}};\n");

        let ms = run_single(&src, "F::g", "NEEDLE");
        assert_eq!(ms.len(), 1, "should match once");

        let snip = &ms[0].snippet;
        // Must be well under the 2 KB threshold (the raw line is ~3 KB).
        assert!(
            snip.len() < 400,
            "trimmed snippet too long ({} bytes): {snip:.80}…",
            snip.len()
        );
        // The match itself must still be present.
        assert!(snip.contains("NEEDLE"), "snippet missing NEEDLE: {snip}");
        // Ellipsis markers indicate truncation on both sides.
        assert!(snip.starts_with('…'), "expected leading ellipsis, got: {snip:.40}");
        assert!(snip.ends_with('…'), "expected trailing ellipsis, got: …{}", &snip[snip.len().saturating_sub(40)..]);
    }

    /// Lines just under 2 KB are returned verbatim (no spurious trimming).
    #[test]
    fn line_under_threshold_not_trimmed() {
        // 2000 chars total: pad + NEEDLE + pad, no ellipsis expected.
        let pad = "x".repeat(996);
        let inner = format!("{pad}NEEDLE(){pad}");
        assert!(inner.len() < 2048, "precondition: inner line under threshold");
        let src = format!("class F {{\n    void g() {{ {inner} }}\n}};\n");

        let ms = run_single(&src, "F::g", "NEEDLE");
        assert_eq!(ms.len(), 1);
        let snip = &ms[0].snippet;
        assert!(!snip.starts_with('…'), "should not trim a line under threshold");
        assert!(!snip.ends_with('…'), "should not trim a line under threshold");
        assert!(snip.contains("NEEDLE"));
    }
}
