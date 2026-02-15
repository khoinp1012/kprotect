use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::info;
use crate::state::AppState;
use crate::core::domain::PatternType;
use crate::core::auth::{parse_pattern, insert_prefix, insert_suffix};
use super::super::utils::{add_zone_to_file, fnv1a_hash};

pub async fn handle_zone_add(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Zone modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: ZONE_ADD;<zone_type>;<pattern>\n".to_string());
    }

    let zone_type = parts[1].trim();
    let pattern_str = parts[2].trim();

    if zone_type != "red" {
        return Ok("ERROR: INVALID_ZONE_TYPE: Only 'red' zones are currently supported\n".to_string());
    }

    let key = {
        let state_lock = state.lock().await;
        state_lock.encryption_key.clone()
    };

    match add_zone_to_file(pattern_str, &key).await {
        Ok(p) => {
            if let Ok(pattern_type) = parse_pattern(&p) {
                let state_lock = state.lock().await;
                match pattern_type {
                    PatternType::Prefix(ref p_str) => {
                        let mut map = state_lock.red_prefix.lock().await;
                        let _ = insert_prefix(&mut *map, p_str);
                    },
                    PatternType::Suffix(ref s_str) => {
                        let mut map = state_lock.red_suffix.lock().await;
                        let _ = insert_suffix(&mut *map, s_str);
                    },
                    PatternType::Exact(ref e_str) => {
                        let mut map = state_lock.red_exact.lock().await;
                        let hash = fnv1a_hash(e_str.as_bytes());
                        let _ = map.insert(hash, 1, 0);
                    }
                }
                info!("✅ Zone added: {} (type: {})", p, zone_type);
            }
            Ok(format!("OK: Zone added: {}\n", p))
        },
        Err(e) => Ok(format!("ERROR: FAILED_TO_ADD_ZONE: {}\n", e))
    }
}

pub async fn handle_zone_remove(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Zone modification requires root privileges\n".to_string());
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: ZONE_REMOVE;<zone_type>;<pattern>\n".to_string());
    }
    let zone_type = parts[1].trim();
    let pattern_str = parts[2].trim();
    if zone_type != "red" { return Ok("ERROR: INVALID_ZONE_TYPE: Only 'red' zones are supported\n".to_string()); }

    let key = { state.lock().await.encryption_key.clone() };
    match super::super::utils::remove_zone_from_file(pattern_str, &key).await {
        Ok(true) => {
            info!("🗑️ Zone removed: {} (Restart required to clear eBPF caches)", pattern_str);
            Ok(format!("OK: Zone removed: {}\n", pattern_str))
        },
        Ok(false) => Ok("ERROR: NOT_FOUND: Zone pattern not found\n".to_string()),
        Err(e) => Ok(format!("ERROR: FAILED_TO_REMOVE_ZONE: {}\n", e))
    }
}

pub async fn handle_zone_list(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let key = { state.lock().await.encryption_key.clone() };
    let zones = super::super::utils::read_zones_file(&key).await?;
    Ok(format!("OK: {}\n", serde_json::to_string(&zones)?))
}

pub async fn handle_pattern_add(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Pattern modification requires root privileges\n".to_string());
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: PATTERN_ADD;<pattern>\n".to_string());
    }
    let pattern_str = parts[1].trim();
    let key = { state.lock().await.encryption_key.clone() };
    
    match super::super::utils::add_enrichment_pattern_to_file(pattern_str, &key).await {
        Ok(_) => {
            info!("✅ Enrichment pattern added: {}", pattern_str);
            Ok(format!("OK: Pattern added: {}\n", pattern_str))
        },
        Err(e) => Ok(format!("ERROR: FAILED_TO_ADD_PATTERN: {}\n", e))
    }
}

pub async fn handle_pattern_remove(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Pattern modification requires root privileges\n".to_string());
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: PATTERN_REMOVE;<pattern>\n".to_string());
    }
    let pattern_str = parts[1].trim();
    let key = { state.lock().await.encryption_key.clone() };
    
    match super::super::utils::remove_enrichment_pattern_from_file(pattern_str, &key).await {
        Ok(true) => {
            info!("🗑️ Enrichment pattern removed: {}", pattern_str);
            Ok(format!("OK: Pattern removed: {}\n", pattern_str))
        },
        Ok(false) => Ok("ERROR: NOT_FOUND: Pattern not found\n".to_string()),
        Err(e) => Ok(format!("ERROR: FAILED_TO_REMOVE_PATTERN: {}\n", e))
    }
}

pub async fn handle_pattern_list(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let key = { state.lock().await.encryption_key.clone() };
    let patterns = super::super::utils::read_enrichment_patterns_file(&key).await?;
    let json = serde_json::json!({ "enrichment_patterns": patterns });
    Ok(format!("OK: {}\n", json))
}
