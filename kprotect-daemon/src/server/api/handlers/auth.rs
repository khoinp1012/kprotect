use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info, warn};
use kprotect_common::MatchMode;
use crate::state::AppState;
use crate::core::auth::rebuild_auth_caches;
use kprotect_common::AuthorizedPattern;
use super::super::utils::{save_authorized_patterns, get_username_from_uid};

pub async fn handle_authorize(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        warn!("🚨 Security Alert: Non-root user (UID={}) tried to authorize a pattern!", caller_uid);
        return Ok("ERROR: PERMISSION: Authorization requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: AUTHORIZE;<pattern>;<mode>;[description]\n".to_string());
    }

    let pattern: Vec<String> = parts[1].split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| if s.len() > 4096 { s[..4096].to_string() } else { s.to_string() })
        .collect();

    if pattern.is_empty() {
        return Ok("ERROR: INVALID_SYNTAX: Cannot authorize an empty process chain (No chain detected)\n".to_string());
    }

    let match_mode = match parts[2].trim() {
        "Exact" => MatchMode::Exact,
        "Suffix" => MatchMode::Suffix,
        _ => return Ok("ERROR: INVALID_MODE: Use 'Exact' or 'Suffix'\n".to_string()),
    };

    let description = if parts.len() > 3 { parts[3].trim().to_string() } else { String::new() };

    let auth_pattern = AuthorizedPattern {
        pattern: pattern.clone(),
        match_mode: match_mode.clone(),
        description: description.clone(),
        authorized_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
    };

    {
        let mut state_lock = state.lock().await;
        state_lock.authorized_patterns.push(auth_pattern.clone());
        let patterns = state_lock.authorized_patterns.clone();
        {
            let AppState { ref mut auth_exact_cache, ref mut auth_suffix_cache, .. } = *state_lock;
            rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);
        }

        let username = get_username_from_uid(caller_uid);
        let _ = state_lock.logger.log_audit(
            "AUTHORIZE",
            &username,
            serde_json::json!({
                "pattern": pattern.join(","),
                "mode": if let MatchMode::Exact = match_mode { "Exact" } else { "Suffix" },
                "description": description
            }),
            true
        );

        // Persistence
        let encryption_key = state_lock.encryption_key.clone();
        save_authorized_patterns(&state_lock.authorized_patterns, &encryption_key)
            .context("Failed to save authorized patterns")?;
    }

    info!("✅ Authorized pattern: {:?} ({:?})", pattern, match_mode);
    Ok(format!("OK: Authorized pattern: {}\n", pattern.join(",")))
}

pub async fn handle_list_auth(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let state_lock = state.lock().await;
    let json = serde_json::to_string(&state_lock.authorized_patterns)?;
    Ok(format!("OK: {}\n", json))
}

pub async fn handle_revoke(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Revocation requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: REVOKE_PATTERN;<pattern>;<mode>\n".to_string());
    }

    let pattern_str = parts[1].trim();
    let mode_str = parts[2].trim();
    
    let match_mode = match mode_str {
        "Exact" => MatchMode::Exact,
        "Suffix" => MatchMode::Suffix,
        _ => return Ok("ERROR: INVALID_MODE: Use 'Exact' or 'Suffix'\n".to_string()),
    };

    let pattern_parts: Vec<String> = pattern_str.split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let mut state_lock = state.lock().await;
    let initial_len = state_lock.authorized_patterns.len();
    
    state_lock.authorized_patterns.retain(|p| {
        p.pattern != pattern_parts || p.match_mode != match_mode
    });

    if state_lock.authorized_patterns.len() < initial_len {
        let patterns = state_lock.authorized_patterns.clone();
        {
            let AppState { ref mut auth_exact_cache, ref mut auth_suffix_cache, .. } = *state_lock;
            rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);
        }

        let username = get_username_from_uid(caller_uid);
        let _ = state_lock.logger.log_audit(
            "REVOKE",
            &username,
            serde_json::json!({ "pattern": pattern_str, "mode": mode_str }),
            true
        );

        let encryption_key = state_lock.encryption_key.clone();
        save_authorized_patterns(&state_lock.authorized_patterns, &encryption_key)?;
        
        info!("🗑️ Revoked pattern: {} ({})", pattern_str, mode_str);
        Ok(format!("OK: Revoked pattern: {}\n", pattern_str))
    } else {
        Ok("ERROR: NOT_FOUND: Pattern not found\n".to_string())
    }
}
