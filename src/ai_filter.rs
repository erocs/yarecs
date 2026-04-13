//! Optional AI false-positive classifier.
//!
//! When the user supplies `--ai-config <path>`, each `ScanMatch` is sent to an
//! OpenAI-compatible `/v1/chat/completions` endpoint and classified as a genuine
//! finding or a false positive.  The result is stored in `ScanMatch::ai_verdict`.
//!
//! Configuration is read from a TOML file so credentials are never typed on the
//! command line (and therefore never appear in shell history or process listings).
//!
//! Example config file (`ai.toml`):
//! ```toml
//! endpoint        = "https://api.openai.com/v1"
//! api_key         = "sk-..."
//! model           = "gpt-4o-mini"
//! # rate_limit_secs = 1.0   # seconds to wait between requests (fractional OK)
//! # prompt          = "Focus on Unreal Engine 5 server-side security context."  # appended to built-in prompt
//! ```

use anyhow::{Context, Result};
use serde::Deserialize;
use std::path::Path;

use crate::engine::{AiClassification, AiVerdict, ScanMatch};

// ---------------------------------------------------------------------------
// Config
// ---------------------------------------------------------------------------

/// Loaded from the file passed to `--ai-config`.
#[derive(Deserialize)]
pub struct AiConfig {
    /// Base URL of an OpenAI-compatible API, e.g. `https://api.openai.com/v1`.
    /// The path `/chat/completions` is appended automatically.
    pub endpoint: String,
    pub api_key:  String,
    pub model:    String,
    /// Seconds to wait between successive AI requests (fractional values allowed).
    /// Useful for staying within provider rate limits.  Defaults to no delay.
    pub rate_limit_secs: Option<f64>,
    /// Additional instructions appended to the built-in system prompt.
    /// The JSON response format requirement is always enforced by the built-in
    /// prompt regardless of what is supplied here.
    pub prompt:          Option<String>,
}

pub fn load_ai_config(path: &Path) -> Result<AiConfig> {
    let text = std::fs::read_to_string(path)
        .with_context(|| format!("cannot read AI config {}", path.display()))?;
    toml::from_str(&text)
        .with_context(|| format!("invalid AI config {}", path.display()))
}

// ---------------------------------------------------------------------------
// Default system prompt
// ---------------------------------------------------------------------------

const DEFAULT_SYSTEM: &str = "\
You are a senior security code reviewer. \
You will be given a static analysis finding and the surrounding source code. \
Determine whether the finding is a genuine security concern, a false positive, \
or whether there is insufficient information in the snippet to make a determination. \
Respond ONLY with a JSON object — no markdown fences, no explanation outside the JSON — \
in exactly this format:\n\
{\"verdict\": \"<true_positive|false_positive|insufficient_info>\", \"reasoning\": \"<one sentence or empty string>\"}\n\
Use \"insufficient_info\" when the provided snippet does not contain enough context \
to make a confident determination; leave \"reasoning\" as an empty string in that case.";

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/// Send a single `ScanMatch` to the configured AI model and return its verdict.
///
/// On network or parsing failure the caller should log a warning and keep the
/// match with `ai_verdict: None` rather than aborting the entire scan.
pub fn classify_match(config: &AiConfig, m: &ScanMatch) -> Result<AiVerdict> {
    let user_msg = format!(
        "Rule: {}\nMessage: {}\nSeverity: {:?}\n\nMatched text: {}\n\nSnippet:\n{}",
        m.rule_name,
        m.message,
        m.severity,
        m.matched_text,
        m.ai_snippet,
    );

    let system_buf;
    let system = match config.prompt.as_deref() {
        None        => DEFAULT_SYSTEM,
        Some(extra) => {
            system_buf = format!("{DEFAULT_SYSTEM}\n\n{extra}");
            &system_buf
        }
    };
    let url = format!("{}/chat/completions", config.endpoint.trim_end_matches('/'));

    let body = serde_json::json!({
        "model": config.model,
        "messages": [
            {"role": "system", "content": system},
            {"role": "user",   "content": user_msg}
        ],
        "temperature": 0
    });

    let resp: serde_json::Value = ureq::post(&url)
        .set("Authorization", &format!("Bearer {}", config.api_key))
        .set("Content-Type", "application/json")
        .send_json(body)
        .context("AI API request failed")?
        .into_json()
        .context("AI API response was not valid JSON")?;

    let content = resp["choices"][0]["message"]["content"]
        .as_str()
        .context("unexpected AI response shape")?;

    // Strip optional markdown code fences the model may wrap around the JSON.
    let content = content
        .trim()
        .trim_start_matches("```json")
        .trim_start_matches("```")
        .trim_end_matches("```")
        .trim();

    let parsed: serde_json::Value =
        serde_json::from_str(content).context("AI response was not parseable JSON")?;

    let verdict_str = parsed["verdict"]
        .as_str()
        .context("AI JSON missing 'verdict' string")?;
    let classification = match verdict_str {
        "true_positive"    => AiClassification::TruePositive,
        "false_positive"   => AiClassification::FalsePositive,
        "insufficient_info" => AiClassification::Insufficient,
        other => anyhow::bail!("AI JSON 'verdict' has unexpected value: {other:?}"),
    };
    let reasoning = match classification {
        AiClassification::Insufficient => String::new(),
        _ => parsed["reasoning"]
            .as_str()
            .unwrap_or("")
            .to_string(),
    };

    Ok(AiVerdict { classification, reasoning })
}
