use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;

#[cfg(not(test))]
const CONFIG_PATH: &str = "/var/lib/kprotect/configs/daemon_config.enc";
#[cfg(test)]
const CONFIG_PATH: &str = "/tmp/kprotect_test_config.enc";

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonConfig {
    pub event_log_retention_days: u32,
    pub audit_log_retention_days: u32,
    pub event_log_enabled: bool,
    pub audit_log_enabled: bool,
    pub engine_enabled: bool,
    pub file_protection_enabled: bool,
    pub sudo_bypass_enabled: bool,
}

impl Default for DaemonConfig {
    fn default() -> Self {
        Self {
            event_log_retention_days: 7,
            audit_log_retention_days: 30,
            event_log_enabled: true,
            audit_log_enabled: true,
            engine_enabled: true,
            file_protection_enabled: true,
            sudo_bypass_enabled: true,
        }
    }
}

pub fn load_config(key: &[u8; 32]) -> Result<DaemonConfig> {
    if !Path::new(CONFIG_PATH).exists() {
        return Ok(DaemonConfig::default());
    }

    let config: DaemonConfig =
        crate::crypto::load_encrypted(CONFIG_PATH, key).context("Failed to load daemon config")?;

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

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    #[test]
    fn test_config_persistence() {
        let key = [0u8; 32];
        let config = DaemonConfig {
            engine_enabled: false,
            event_log_retention_days: 99,
            ..DaemonConfig::default()
        };

        // Clean up before test
        let _ = fs::remove_file(CONFIG_PATH);

        // Save
        save_config(&config, &key).expect("Failed to save");

        // Load
        let loaded = load_config(&key).expect("Failed to load");

        // Verify
        assert!(!loaded.engine_enabled);
        assert_eq!(loaded.event_log_retention_days, 99);

        // Clean up after test
        let _ = fs::remove_file(CONFIG_PATH);
    }

    #[test]
    fn test_config_default_if_missing() {
        let key = [0u8; 32];
        // Clean up before test
        let _ = fs::remove_file(CONFIG_PATH);

        // Load missing file
        let loaded = load_config(&key).expect("Failed to load default");

        // Verify defaults
        assert!(loaded.engine_enabled);
        assert_eq!(loaded.event_log_retention_days, 7);
    }
}
