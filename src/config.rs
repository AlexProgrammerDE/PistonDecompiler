use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub data_dir: PathBuf,
    pub listen: String,
    pub web_dir: PathBuf,
    pub browser_origins: Vec<String>,
    pub ghidra_home: Option<PathBuf>,
    pub ghidra_timeout_secs: u64,
    pub ghidra_gui: bool,
    pub ai: AiConfig,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
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
    pub max_attempts: u32,
    pub request_timeout_secs: u64,
    pub batch_enabled: bool,
    pub batch_price_multiplier: f64,
    pub batch_size: usize,
    pub decisions: Option<DecisionConfig>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct DecisionConfig {
    pub endpoint: String,
    pub model: String,
    pub input_usd_per_million: f64,
    pub output_usd_per_million: f64,
    pub confidence_threshold: f64,
    pub max_input_bytes: usize,
}
impl Default for DecisionConfig {
    fn default() -> Self {
        Self {
            endpoint: "https://openrouter.ai/api/alpha/decisions".into(),
            model: "typesafe/jev-1.13".into(),
            input_usd_per_million: 0.042,
            output_usd_per_million: 0.0,
            confidence_threshold: 0.95,
            max_input_bytes: 96000,
        }
    }
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
            ghidra_gui: false,
            ai: AiConfig::default(),
        }
    }
}
impl Default for AiConfig {
    fn default() -> Self {
        Self {
            base_url: "https://openrouter.ai/api/v1".into(),
            api_key_env: "PISTONDECOMPILER_AI_API_KEY".into(),
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
            max_attempts: 3,
            request_timeout_secs: 120,
            batch_enabled: false,
            batch_price_multiplier: 1.0,
            batch_size: 500,
            decisions: None,
        }
    }
}
impl Config {
    pub fn load(path: &std::path::Path) -> Result<Self> {
        let mut config: Self = if path.exists() {
            toml::from_str(&std::fs::read_to_string(path)?)
                .context("invalid PistonDecompiler configuration")?
        } else {
            Self::default()
        };
        if path.exists() {
            let absolute = std::fs::canonicalize(path)?;
            let base = absolute
                .parent()
                .context("Configuration has no parent directory")?;
            if config.data_dir.is_relative() {
                config.data_dir = base.join(&config.data_dir);
            }
            if config.web_dir.is_relative() {
                config.web_dir = base.join(&config.web_dir);
            }
            if let Some(home) = &mut config.ghidra_home
                && home.is_relative()
            {
                *home = base.join(&*home);
            }
        }
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
        if let Some(d) = &ai.decisions {
            let endpoint =
                reqwest::Url::parse(&d.endpoint).context("invalid Decisions endpoint")?;
            ensure!(
                matches!(endpoint.scheme(), "http" | "https"),
                "invalid Decisions endpoint scheme"
            );
            ensure!(!d.model.trim().is_empty(), "configure a decision model");
            ensure!(
                (4096..=100000).contains(&d.max_input_bytes),
                "decision max_input_bytes must be 4096..100000"
            );
            ensure!(
                d.input_usd_per_million.is_finite()
                    && d.input_usd_per_million > 0.0
                    && d.output_usd_per_million.is_finite()
                    && d.output_usd_per_million >= 0.0,
                "decision prices must have positive input and nonnegative output rates"
            );
            ensure!(
                d.confidence_threshold.is_finite()
                    && d.confidence_threshold > 0.0
                    && d.confidence_threshold <= 1.0,
                "decision threshold must be in (0,1]"
            );
            ensure!(
                !ai.batch_enabled,
                "Decisions routing requires local workers; disable provider batches"
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
        if crate::decisions::is_decision_stage(stage)
            && let Some(d) = &self.decisions
        {
            (d.input_usd_per_million, d.output_usd_per_million)
        } else if stage == "escalate" {
            (
                self.escalation_input_usd_per_million,
                self.escalation_output_usd_per_million,
            )
        } else {
            (self.input_usd_per_million, self.output_usd_per_million)
        }
    }
    pub fn model_for(&self, stage: &str) -> &str {
        if crate::decisions::is_decision_stage(stage)
            && let Some(d) = &self.decisions
        {
            &d.model
        } else if stage == "escalate" {
            &self.escalation_model
        } else {
            &self.model
        }
    }
}

#[cfg(test)]
mod persistence_tests {
    use super::*;
    #[test]
    fn config_relative_paths_stay_with_the_config_file() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("piston.toml");
        std::fs::write(
            &path,
            "data_dir = 'data'\nweb_dir = 'web'\nghidra_home = 'ghidra'\n",
        )
        .unwrap();
        let config = Config::load(&path).unwrap();
        assert_eq!(config.data_dir, dir.path().join("data"));
        assert_eq!(config.web_dir, dir.path().join("web"));
        assert_eq!(config.ghidra_home, Some(dir.path().join("ghidra")));
    }
}
