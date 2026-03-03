use crate::config::save_config;
use crate::state::{AppState, RulesState};
use anyhow::Result;
use log::info;
use std::sync::{Arc, RwLock};

pub async fn handle_set_engine(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    set_engine_internal(&state.rules, &state.encryption_key, cmd, caller_uid).await
}

pub async fn handle_set_file_protection(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    set_file_protection_internal(&state.rules, &state.encryption_key, cmd, caller_uid).await
}

pub async fn handle_set_sudo_bypass(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    set_sudo_bypass_internal(&state.rules, &state.encryption_key, cmd, caller_uid).await
}

async fn set_engine_internal(
    rules_lock: &RwLock<crate::state::RulesState>,
    key: &[u8; 32],
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Configuration modification requires root privileges\n".to_string(),
        );
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SET_ENGINE;true|false\n".to_string());
    }

    let enabled = parts[1].trim().parse::<bool>().unwrap_or(true);

    {
        let mut rules = rules_lock.write().unwrap();
        rules.config.engine_enabled = enabled;
        save_config(&rules.config, key)?;
    }

    info!("⚙️ Configuration: Engine toggled to {}", enabled);
    Ok("OK: Engine status updated\n".to_string())
}

async fn set_file_protection_internal(
    rules_lock: &RwLock<crate::state::RulesState>,
    key: &[u8; 32],
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Configuration modification requires root privileges\n".to_string(),
        );
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SET_FILE_PROTECTION;true|false\n".to_string());
    }

    let enabled = parts[1].trim().parse::<bool>().unwrap_or(true);

    {
        let mut rules = rules_lock.write().unwrap();
        rules.config.file_protection_enabled = enabled;
        save_config(&rules.config, key)?;
    }

    info!("⚙️ Configuration: File Protection toggled to {}", enabled);
    Ok("OK: File Protection status updated\n".to_string())
}

async fn set_sudo_bypass_internal(
    rules_lock: &RwLock<crate::state::RulesState>,
    key: &[u8; 32],
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Configuration modification requires root privileges\n".to_string(),
        );
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SET_SUDO_BYPASS;true|false\n".to_string());
    }

    let enabled = parts[1].trim().parse::<bool>().unwrap_or(true);

    {
        let mut rules = rules_lock.write().unwrap();
        rules.config.sudo_bypass_enabled = enabled;
        save_config(&rules.config, key)?;
    }

    info!("⚙️ Configuration: Sudo Bypass toggled to {}", enabled);
    Ok("OK: Sudo Bypass status updated\n".to_string())
}

pub async fn handle_export_config(state: &Arc<AppState>) -> Result<String> {
    // 1. Async data collection (Files & DB)
    let zones = crate::server::api::utils::read_zones_file(&state.encryption_key).await?;
    let enrichment =
        crate::server::api::utils::read_enrichment_patterns_file(&state.encryption_key).await?;
    let notification_rules = state.notification_manager.get_rules().await;

    // 2. Sync data collection (Memory state)
    let backup = {
        let rules = state.rules.read().unwrap();
        kprotect_common::KProtectBackup {
            version: env!("CARGO_PKG_VERSION").to_string(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_secs(),
            zones: kprotect_common::ZonesConfig {
                red_zones: zones.red_zones,
                green_zones: zones.green_zones,
            },
            enrichment: kprotect_common::EnrichmentConfig {
                enrichment_patterns: enrichment,
            },
            authorized_patterns: rules.authorized_patterns.clone(),
            sudo_rules: rules.sudo_rules.clone(),
            notification_rules,
            log_config: kprotect_common::LogConfig {
                event_log_retention_days: rules.config.event_log_retention_days,
                audit_log_retention_days: rules.config.audit_log_retention_days,
                event_log_enabled: rules.config.event_log_enabled,
                audit_log_enabled: rules.config.audit_log_enabled,
            },
        }
    };

    Ok(format!("OK: {}\n", serde_json::to_string(&backup)?))
}

pub async fn handle_import_config(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Configuration import requires root privileges\n".to_string(),
        );
    }

    let json_str = match cmd.strip_prefix("IMPORT_CONFIG ") {
        Some(s) => s,
        None => return Ok("ERROR: INVALID_SYNTAX: Usage: IMPORT_CONFIG <json>\n".to_string()),
    };

    let backup: kprotect_common::KProtectBackup = match serde_json::from_str(json_str) {
        Ok(b) => b,
        Err(e) => return Ok(format!("ERROR: INVALID_JSON: {}\n", e)),
    };

    info!(
        "📥 Importing atomic configuration backup (v{})...",
        backup.version
    );

    // 1. Update memory state for RulesState (Authorized Patterns, Sudo Rules, App Config)
    {
        let mut rules = state.rules.write().unwrap();
        rules.authorized_patterns = backup.authorized_patterns.clone();
        rules.sudo_rules = backup.sudo_rules.clone();
        rules.config.event_log_retention_days = backup.log_config.event_log_retention_days;
        rules.config.audit_log_retention_days = backup.log_config.audit_log_retention_days;
        rules.config.event_log_enabled = backup.log_config.event_log_enabled;
        rules.config.audit_log_enabled = backup.log_config.audit_log_enabled;

        // Rebuild caches
        let patterns = rules.authorized_patterns.clone();
        let RulesState {
            auth_exact_cache,
            auth_suffix_cache,
            ..
        } = &mut *rules;
        crate::core::auth::rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);
    }

    // 2. Update Notification Manager
    state
        .notification_manager
        .update_rules(backup.notification_rules.clone())
        .await;

    // 3. Persist everything to disk (Atomic write per file)
    let key = &state.encryption_key;

    // Save Zones
    let zones_file = crate::migration::ZonesFile {
        green_zones: backup.zones.green_zones,
        red_zones: backup.zones.red_zones,
    };
    crate::crypto::save_encrypted(&zones_file, crate::server::api::utils::ZONES_ENC, key)?;

    // Save Enrichment
    crate::crypto::save_encrypted(
        &backup.enrichment.enrichment_patterns,
        crate::server::api::utils::ENRICHMENT_ENC,
        key,
    )?;

    // Save Auth Patterns
    crate::crypto::save_encrypted(
        &backup.authorized_patterns,
        crate::server::api::utils::AUTHORIZED_PATTERNS_PATH,
        key,
    )?;

    // Save Sudo Rules
    crate::crypto::save_encrypted(
        &backup.sudo_rules,
        crate::server::api::utils::SUDO_RULES_PATH,
        key,
    )?;

    // Save Notifications
    crate::crypto::save_encrypted(
        &backup.notification_rules,
        crate::server::api::utils::NOTIFICATION_RULES_PATH,
        key,
    )?;

    // Save Daemon Config
    {
        let rules = state.rules.read().unwrap();
        save_config(&rules.config, key)?;
    }

    info!("✅ Atomic configuration import successful");
    Ok("OK: Configuration imported successfully\n".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::DaemonConfig;
    use crate::core::domain::ChainTrieNode;
    use crate::state::RulesState;
    use std::collections::HashMap;

    static TEST_MUTEX: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn setup_test_rules() -> (RwLock<RulesState>, [u8; 32]) {
        let rules = RwLock::new(RulesState {
            authorized_patterns: vec![],
            sudo_rules: vec![],
            auth_exact_cache: HashMap::new(),
            auth_suffix_cache: ChainTrieNode::new(),
            config: DaemonConfig::default(),
        });
        (rules, [0u8; 32])
    }

    #[tokio::test]
    async fn test_set_engine_success() {
        let (rules, key) = setup_test_rules();
        let res = {
            let _lock = TEST_MUTEX.lock().unwrap();
            set_engine_internal(&rules, &key, "SET_ENGINE;false", 0)
        }
        .await
        .unwrap();
        assert_eq!(res, "OK: Engine status updated\n");
        assert!(!rules.read().unwrap().config.engine_enabled);
    }

    #[tokio::test]
    async fn test_set_engine_permission_denied() {
        let (rules, key) = setup_test_rules();
        let res = {
            let _lock = TEST_MUTEX.lock().unwrap();
            set_engine_internal(&rules, &key, "SET_ENGINE;false", 1000)
        }
        .await
        .unwrap();
        assert!(res.contains("ERROR: PERMISSION"));
        assert!(rules.read().unwrap().config.engine_enabled); // Still true
    }

    #[tokio::test]
    async fn test_set_engine_invalid_syntax() {
        let (rules, key) = setup_test_rules();
        let res = {
            let _lock = TEST_MUTEX.lock().unwrap();
            set_engine_internal(&rules, &key, "SET_ENGINE", 0)
        }
        .await
        .unwrap();
        assert!(res.contains("ERROR: INVALID_SYNTAX"));
    }

    #[tokio::test]
    async fn test_set_file_protection_success() {
        let (rules, key) = setup_test_rules();
        let res = {
            let _lock = TEST_MUTEX.lock().unwrap();
            set_file_protection_internal(&rules, &key, "SET_FILE_PROTECTION;false", 0)
        }
        .await
        .unwrap();
        assert_eq!(res, "OK: File Protection status updated\n");
        assert!(!rules.read().unwrap().config.file_protection_enabled);
    }

    #[tokio::test]
    async fn test_set_sudo_bypass_success() {
        let (rules, key) = setup_test_rules();
        let res = {
            let _lock = TEST_MUTEX.lock().unwrap();
            set_sudo_bypass_internal(&rules, &key, "SET_SUDO_BYPASS;false", 0)
        }
        .await
        .unwrap();
        assert_eq!(res, "OK: Sudo Bypass status updated\n");
        assert!(!rules.read().unwrap().config.sudo_bypass_enabled);
    }
}
