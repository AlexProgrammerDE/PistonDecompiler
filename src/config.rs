use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    pub listen: String,
    pub web_dir: PathBuf,
    pub browser_origins: Vec<String>,
    pub ghidra_home: Option<PathBuf>,
    pub ghidra_timeout_secs: u64,
    pub ai: AiConfig,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AiConfig {
    pub base_url: String,
    pub api_key_env: String,
    pub model: String,
    pub escalation_model: String,
    pub concurrency: usize,
    pub budget_usd: f64,
    pub input_usd_per_million: f64,
    pub output_usd_per_million: f64,
    pub escalation_input_usd_per_million: f64,
    pub escalation_output_usd_per_million: f64,
    pub max_input_bytes: usize,
    pub max_output_tokens: u32,
    pub confidence_threshold: f64,
    pub max_attempts: u32,
    pub request_timeout_secs: u64,
    pub batch_enabled: bool,
    pub batch_price_multiplier: f64,
    pub batch_size: usize,
}
impl Default for Config {
    fn default() -> Self {
        Self {
            data_dir: "data".into(),
            listen: "127.0.0.1:7070".into(),
            web_dir: "web/dist".into(),
            browser_origins: Vec::new(),
            ghidra_home: std::env::var_os("GHIDRA_HOME").map(Into::into),
            ghidra_timeout_secs: 7200,
            ai: AiConfig::default(),
        }
    }
}
impl Default for AiConfig {
    fn default() -> Self {
        Self {
            base_url: "https://openrouter.ai/api/v1".into(),
            api_key_env: "PISTON_AI_API_KEY".into(),
            model: String::new(),
            escalation_model: String::new(),
            concurrency: 4,
            budget_usd: 5.0,
            input_usd_per_million: 0.0,
            output_usd_per_million: 0.0,
            escalation_input_usd_per_million: 0.0,
            escalation_output_usd_per_million: 0.0,
            max_input_bytes: 24000,
            max_output_tokens: 1000,
            confidence_threshold: 0.7,
            max_attempts: 3,
            request_timeout_secs: 120,
            batch_enabled: false,
            batch_price_multiplier: 1.0,
            batch_size: 500,
        }
    }
}
impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let config: Self = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)
                .context("invalid piston configuration")?
        } else {
            Self::default()
        };
        let ai = &config.ai;
        ensure!(
            (1..=128).contains(&ai.concurrency),
            "concurrency must be 1..128"
        );
        ensure!(
            (4096..=100000).contains(&ai.max_input_bytes),
            "max_input_bytes must be 4096..100000"
        );
        ensure!(
            (128..=16000).contains(&ai.max_output_tokens),
            "max_output_tokens must be 128..16000"
        );
        ensure!(
            (1..=10).contains(&ai.max_attempts),
            "max_attempts must be 1..10"
        );
        ensure!(
            (1..=10000).contains(&ai.batch_size),
            "batch_size must be 1..10000"
        );
        ensure!(
            ai.budget_usd.is_finite() && ai.budget_usd > 0.0,
            "budget must be positive"
        );
        ensure!(
            ai.confidence_threshold.is_finite() && (0.0..=1.0).contains(&ai.confidence_threshold),
            "invalid confidence threshold"
        );
        ensure!(
            ai.request_timeout_secs > 0 && config.ghidra_timeout_secs > 0,
            "timeouts must be positive"
        );
        ensure!(
            ai.batch_price_multiplier.is_finite() && ai.batch_price_multiplier > 0.0,
            "invalid batch price multiplier"
        );
        for price in [
            ai.input_usd_per_million,
            ai.output_usd_per_million,
            ai.escalation_input_usd_per_million,
            ai.escalation_output_usd_per_million,
        ] {
            ensure!(
                price.is_finite() && price >= 0.0,
                "prices must be finite and nonnegative"
            );
        }
        Ok(config)
    }
}
impl AiConfig {
    pub fn configured(&self) -> bool {
        !self.model.is_empty()
            && std::env::var(&self.api_key_env).is_ok_and(|v| !v.is_empty())
            && self.input_usd_per_million > 0.0
            && self.output_usd_per_million > 0.0
    }
    pub fn rates(&self, stage: &str) -> (f64, f64) {
        if stage == "escalate" {
            (
                self.escalation_input_usd_per_million,
                self.escalation_output_usd_per_million,
            )
        } else {
            (self.input_usd_per_million, self.output_usd_per_million)
        }
    }
    pub fn model_for(&self, stage: &str) -> &str {
        if stage == "escalate" {
            &self.escalation_model
        } else {
            &self.model
        }
    }
}
