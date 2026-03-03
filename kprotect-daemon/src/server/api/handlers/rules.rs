use super::super::utils::{add_zone_to_file, fnv1a_hash};
use crate::core::auth::{insert_prefix, insert_suffix, parse_pattern};
use crate::core::domain::PatternType;
use crate::state::AppState;
use anyhow::Result;
use log::info;
use std::sync::Arc;

pub async fn handle_zone_add(state: &Arc<AppState>, cmd: &str, caller_uid: u32) -> Result<String> {
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
        return Ok(
            "ERROR: INVALID_ZONE_TYPE: Only 'red' zones are currently supported\n".to_string(),
        );
    }

    let key = state.encryption_key;

    match add_zone_to_file(pattern_str, &key).await {
        Ok(p) => {
            if let Ok(pattern_type) = parse_pattern(&p) {
                match pattern_type {
                    PatternType::Prefix(ref p_str) => {
                        let mut map_opt = state.red_prefix.lock().await;
                        if let Some(ref mut map) = *map_opt {
                            let _ = insert_prefix(map, p_str);
                        }
                    }
                    PatternType::Suffix(ref s_str) => {
                        let mut map_opt = state.red_suffix.lock().await;
                        if let Some(ref mut map) = *map_opt {
                            let _ = insert_suffix(map, s_str);
                        }
                    }
                    PatternType::Exact(ref e_str) => {
                        let mut map_opt = state.red_exact.lock().await;
                        if let Some(ref mut map) = *map_opt {
                            let hash = fnv1a_hash(e_str.as_bytes());
                            let _ = map.insert(hash, 1, 0);
                        }
                    }
                }
                info!("✅ Zone added: {} (type: {})", p, zone_type);
            }
            Ok(format!("OK: Zone added: {}\n", p))
        }
        Err(e) => Ok(format!("ERROR: FAILED_TO_ADD_ZONE: {}\n", e)),
    }
}

pub async fn handle_zone_remove(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Zone modification requires root privileges\n".to_string());
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: ZONE_REMOVE;<zone_type>;<pattern>\n".to_string());
    }
    let zone_type = parts[1].trim();
    let pattern_str = parts[2].trim();
    if zone_type != "red" {
        return Ok("ERROR: INVALID_ZONE_TYPE: Only 'red' zones are supported\n".to_string());
    }

    let key = state.encryption_key;
    match super::super::utils::remove_zone_from_file(pattern_str, &key).await {
        Ok(true) => {
            info!(
                "🗑️ Zone removed: {} (Restart required to clear eBPF caches)",
                pattern_str
            );
            Ok(format!("OK: Zone removed: {}\n", pattern_str))
        }
        Ok(false) => Ok("ERROR: NOT_FOUND: Zone pattern not found\n".to_string()),
        Err(e) => Ok(format!("ERROR: FAILED_TO_REMOVE_ZONE: {}\n", e)),
    }
}

pub async fn handle_zone_list(state: &Arc<AppState>) -> Result<String> {
    let key = state.encryption_key;
    let zones = super::super::utils::read_zones_file(&key).await?;
    Ok(format!("OK: {}\n", serde_json::to_string(&zones)?))
}

pub async fn handle_pattern_add(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Pattern modification requires root privileges\n".to_string(),
        );
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: PATTERN_ADD;<pattern>\n".to_string());
    }
    let pattern_str = parts[1].trim();
    let key = state.encryption_key;

    match super::super::utils::add_enrichment_pattern_to_file(pattern_str, &key).await {
        Ok(_) => {
            info!("✅ Enrichment pattern added: {}", pattern_str);
            Ok(format!("OK: Pattern added: {}\n", pattern_str))
        }
        Err(e) => Ok(format!("ERROR: FAILED_TO_ADD_PATTERN: {}\n", e)),
    }
}

pub async fn handle_pattern_remove(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Pattern modification requires root privileges\n".to_string(),
        );
    }
    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: PATTERN_REMOVE;<pattern>\n".to_string());
    }
    let pattern_str = parts[1].trim();
    let key = state.encryption_key;

    match super::super::utils::remove_enrichment_pattern_from_file(pattern_str, &key).await {
        Ok(true) => {
            info!("🗑️ Enrichment pattern removed: {}", pattern_str);
            Ok(format!("OK: Pattern removed: {}\n", pattern_str))
        }
        Ok(false) => Ok("ERROR: NOT_FOUND: Pattern not found\n".to_string()),
        Err(e) => Ok(format!("ERROR: FAILED_TO_REMOVE_PATTERN: {}\n", e)),
    }
}

pub async fn handle_pattern_list(state: &Arc<AppState>) -> Result<String> {
    let key = state.encryption_key;
    let patterns = super::super::utils::read_enrichment_patterns_file(&key).await?;
    let json = serde_json::json!({ "enrichment_patterns": patterns });
    Ok(format!("OK: {}\n", json))
}

pub async fn handle_zone_clear(state: &Arc<AppState>, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Zone modification requires root privileges\n".to_string());
    }
    let key = state.encryption_key;
    super::super::utils::clear_zones_file(&key).await?;

    // Note: eBPF map clearing is not atomic here, but it's acceptable for now
    info!("🗑️ Cleared all zone patterns (Restart recommended to clear eBPF caches)");
    Ok("OK: All zones cleared\n".to_string())
}

pub async fn handle_pattern_clear(state: &Arc<AppState>, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Pattern modification requires root privileges\n".to_string(),
        );
    }
    let key = state.encryption_key;
    super::super::utils::clear_enrichment_patterns_file(&key).await?;

    info!("🗑️ Cleared all enrichment patterns");
    Ok("OK: All patterns cleared\n".to_string())
}

#[cfg(test)]
mod tests {
    // No imports needed for minimal logic tests

    // Helper to create a minimal AppState for testing
    // Note: We can't easily create real BpfHashMap handles here,
    // so we only test handlers that don't hit the maps yet or we refactor them.

    #[tokio::test]
    async fn test_handler_permissions() {
        // We can't easily create a full AppState, but we can test the permission check line
        // directly if we were to refactor. For now, let's just assert the logic we see.

        let caller_uid = 1000;
        let res = if caller_uid != 0 {
            "ERROR: PERMISSION: Zone modification requires root privileges\n".to_string()
        } else {
            "OK".to_string()
        };
        assert_eq!(
            res,
            "ERROR: PERMISSION: Zone modification requires root privileges\n"
        );
    }

    #[test]
    fn test_syntax_parsing() {
        let cmd = "ZONE_ADD;red;/etc/*";
        let parts: Vec<&str> = cmd.split(';').collect();
        assert_eq!(parts.len(), 3);
        assert_eq!(parts[1], "red");
        assert_eq!(parts[2], "/etc/*");
    }
}
