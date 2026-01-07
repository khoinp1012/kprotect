use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

const CONFIG_PATH: &str = "/var/lib/kprotect/configs/daemon_config.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub event_log_retention_days: u32,
    pub audit_log_retention_days: u32,
    pub event_log_enabled: bool,
    pub audit_log_enabled: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            event_log_retention_days: 7,
            audit_log_retention_days: 30,
            event_log_enabled: true,
            audit_log_enabled: true,
        }
    }
}

pub fn load_config(key: &[u8; 32]) -> Result<DaemonConfig> {
    if !Path::new(CONFIG_PATH).exists() {
        return Ok(DaemonConfig::default());
    }

    let config: DaemonConfig = crate::crypto::load_encrypted(CONFIG_PATH, key)
        .context("Failed to load daemon config")?;

    Ok(config)
}

pub fn save_config(config: &DaemonConfig, key: &[u8; 32]) -> Result<()> {
    // Ensure directory exists
    if let Some(parent) = Path::new(CONFIG_PATH).parent() {
        fs::create_dir_all(parent)?;
    }

    crate::crypto::save_encrypted(config, CONFIG_PATH, key)
        .context("Failed to save daemon config")?;

    Ok(())
}
