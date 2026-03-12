//! Rule loading and data types.
//!
//! Rules are defined in a TOML file and loaded once at startup.  Each rule compiles
//! its regex pattern(s) into [`grep::regex::RegexMatcher`] instances (ripgrep's engine)
//! so that repeated scanning is allocation-free at match time.
//!
//! A rule fires when:
//! 1. The trigger `pattern` matches somewhere in a scope body that satisfies `scope_filter`.
//! 2. Every entry in `chain` is also satisfied (AND semantics; empty chain always passes).

use anyhow::{Context, Result};
use grep::regex::{RegexMatcher, RegexMatcherBuilder};
use serde::Deserialize;
use std::path::Path;

// ---------------------------------------------------------------------------
// Severity
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl std::fmt::Display for Severity {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Severity::Error   => write!(f, "error"),
            Severity::Warning => write!(f, "warning"),
            Severity::Info    => write!(f, "info"),
        }
    }
}

// ---------------------------------------------------------------------------
// Scope filter
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub enum FilterSegment {
    Exact(String),
    Any,
    AnyDepth,
}

#[derive(Debug, Clone)]
pub struct ScopeFilter {
    segments: Vec<FilterSegment>,
}

impl ScopeFilter {
    /// Parse a `::` separated filter string into segments.
    ///
    /// Segment meanings:
    /// - `**` → [`FilterSegment::AnyDepth`] — matches zero or more path levels
    /// - `*`  → [`FilterSegment::Any`] — matches exactly one path level (any name)
    /// - anything else → [`FilterSegment::Exact`] — literal name match
    pub fn parse(s: &str) -> Self {
        let segments = s
            .split("::")
            .map(|seg| match seg {
                "**" => FilterSegment::AnyDepth,
                "*"  => FilterSegment::Any,
                other => FilterSegment::Exact(other.to_string()),
            })
            .collect();
        ScopeFilter { segments }
    }

    /// Test whether a scope path (e.g. `&["MyNS", "MyClass", "myMethod"]`) satisfies
    /// this filter.  Matching is recursive: `**` tries every possible number of
    /// consumed path elements before delegating to the rest of the filter pattern.
    pub fn matches(&self, path: &[&str]) -> bool {
        Self::match_segs(&self.segments, path)
    }

    fn match_segs(filter: &[FilterSegment], path: &[&str]) -> bool {
        match filter.first() {
            None => path.is_empty(),
            Some(FilterSegment::AnyDepth) => {
                for i in 0..=path.len() {
                    if Self::match_segs(&filter[1..], &path[i..]) {
                        return true;
                    }
                }
                false
            }
            Some(FilterSegment::Any) => {
                !path.is_empty() && Self::match_segs(&filter[1..], &path[1..])
            }
            Some(FilterSegment::Exact(s)) => {
                !path.is_empty() && path[0] == s.as_str()
                    && Self::match_segs(&filter[1..], &path[1..])
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Search target
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
pub enum SearchTarget {
    All,
    Comments,
    Code,
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

/// Where a chained pattern must be found relative to the trigger match.
#[derive(Debug, Clone, PartialEq)]
pub enum ChainRelationship {
    /// Anywhere after the trigger's end byte, within the same matched scope body.
    After,
    /// Anywhere before the trigger's start byte, within the same matched scope body.
    Before,
    /// Anywhere within the same matched scope body (no position constraint).
    AnywhereInMethod,
    /// Anywhere within the body of the nearest enclosing Class or Struct scope.
    AnywhereInClass,
    /// Anywhere within the body of the nearest enclosing Namespace scope.
    AnywhereInNamespace,
}

/// A compiled chained pattern that must co-exist with the trigger match.
pub struct ChainedPattern {
    pub matcher: RegexMatcher,
    pub relationship: ChainRelationship,
}

// ---------------------------------------------------------------------------
// Rule
// ---------------------------------------------------------------------------

/// A fully compiled rule ready for scanning.
pub struct Rule {
    pub name: String,
    /// Compiled trigger pattern (ripgrep's `RegexMatcher`).
    pub matcher: RegexMatcher,
    /// Scope filter that gates which scopes are searched.
    /// `None` means "search every named scope in the file".
    pub scope_filter: Option<ScopeFilter>,
    pub message: String,
    pub severity: Severity,
    /// Controls which bytes within a scope body are fed to the matcher.
    pub search_target: SearchTarget,
    /// Additional patterns that must ALL match (AND chain) for the rule to fire.
    /// Empty = no chain conditions (always fires on trigger match).
    pub chain: Vec<ChainedPattern>,
}

// ---------------------------------------------------------------------------
// TOML deserialization
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct RuleConfig {
    name: String,
    pattern: String,
    scope: Option<String>,
    message: String,
    #[serde(default = "default_severity")]
    severity: Severity,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    word: bool,
    #[serde(default)]
    multiline: bool,
    #[serde(default)]
    search: SearchTargetConfig,
    #[serde(default)]
    chain: Vec<ChainConfig>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "lowercase")]
enum SearchTargetConfig {
    #[default]
    All,
    Comments,
    Code,
}

#[derive(Debug, Deserialize)]
struct ChainConfig {
    pattern: String,
    relationship: ChainRelationshipConfig,
    #[serde(default)]
    case_insensitive: bool,
    #[serde(default)]
    word: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ChainRelationshipConfig {
    After,
    Before,
    AnywhereInMethod,
    AnywhereInClass,
    AnywhereInNamespace,
}

fn default_severity() -> Severity { Severity::Warning }

#[derive(Debug, Deserialize)]
struct Config {
    rules: Vec<RuleConfig>,
}

pub fn load_rules(path: &Path) -> Result<Vec<Rule>> {
    let content = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read config: {}", path.display()))?;

    let config: Config = toml::from_str(&content)
        .with_context(|| format!("cannot parse config: {}", path.display()))?;

    config.rules.into_iter().map(|rc| {
        let matcher = RegexMatcherBuilder::new()
            .case_insensitive(rc.case_insensitive)
            .word(rc.word)
            .multi_line(rc.multiline)
            .build(&rc.pattern)
            .with_context(|| format!("invalid regex in rule '{}': {}", rc.name, rc.pattern))?;

        let search_target = match rc.search {
            SearchTargetConfig::All      => SearchTarget::All,
            SearchTargetConfig::Comments => SearchTarget::Comments,
            SearchTargetConfig::Code     => SearchTarget::Code,
        };

        let chain = rc.chain.into_iter().map(|cc| {
            let chain_matcher = RegexMatcherBuilder::new()
                .case_insensitive(cc.case_insensitive)
                .word(cc.word)
                .build(&cc.pattern)
                .with_context(|| format!(
                    "invalid chain regex in rule '{}': {}", rc.name, cc.pattern
                ))?;
            let relationship = match cc.relationship {
                ChainRelationshipConfig::After              => ChainRelationship::After,
                ChainRelationshipConfig::Before             => ChainRelationship::Before,
                ChainRelationshipConfig::AnywhereInMethod   => ChainRelationship::AnywhereInMethod,
                ChainRelationshipConfig::AnywhereInClass    => ChainRelationship::AnywhereInClass,
                ChainRelationshipConfig::AnywhereInNamespace => ChainRelationship::AnywhereInNamespace,
            };
            Ok(ChainedPattern { matcher: chain_matcher, relationship })
        }).collect::<Result<Vec<_>>>()?;

        Ok(Rule {
            name: rc.name,
            matcher,
            scope_filter: rc.scope.map(|s| ScopeFilter::parse(&s)),
            message: rc.message,
            severity: rc.severity,
            search_target,
            chain,
        })
    }).collect()
}
