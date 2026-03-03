use super::super::utils::{get_username_from_uid, save_authorized_patterns};
use crate::core::auth::rebuild_auth_caches;
use crate::state::AppState;
use anyhow::{Context, Result};
use kprotect_common::AuthorizedPattern;
use kprotect_common::MatchMode;
use log::{info, warn};
use std::sync::Arc;

pub async fn handle_authorize(state: &Arc<AppState>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        warn!(
            "🚨 Security Alert: Non-root user (UID={}) tried to authorize a pattern!",
            caller_uid
        );
        return Ok("ERROR: PERMISSION: Authorization requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok(
            "ERROR: INVALID_SYNTAX: Usage: AUTHORIZE;<pattern>;<mode>;[description]\n".to_string(),
        );
    }

    let pattern: Vec<String> = parts[1]
        .split(',')
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .map(|s| {
            if s.len() > 4096 {
                s[..4096].to_string()
            } else {
                s.to_string()
            }
        })
        .collect();

    if pattern.is_empty() {
        return Ok(
            "ERROR: INVALID_SYNTAX: Cannot authorize an empty process chain (No chain detected)\n"
                .to_string(),
        );
    }

    let match_mode = match parts[2].trim() {
        "Exact" => MatchMode::Exact,
        "Suffix" => MatchMode::Suffix,
        _ => return Ok("ERROR: INVALID_MODE: Use 'Exact' or 'Suffix'\n".to_string()),
    };

    let description = if parts.len() > 3 {
        parts[3].trim().to_string()
    } else {
        String::new()
    };

    let auth_pattern = AuthorizedPattern {
        pattern: pattern.clone(),
        match_mode,
        description: description.clone(),
        authorized_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    };

    let mut rules = state.rules.write().unwrap();
    rules.authorized_patterns.push(auth_pattern.clone());
    let patterns = rules.authorized_patterns.clone();

    // Destructure to avoid multiple mutable borrows through the guard
    let crate::state::RulesState {
        ref mut auth_exact_cache,
        ref mut auth_suffix_cache,
        ..
    } = *rules;
    rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);

    let username = get_username_from_uid(caller_uid);
    let _ = state.logger.log_audit(
        "AUTHORIZE",
        &username,
        serde_json::json!({
            "pattern": pattern.join(","),
            "mode": if let MatchMode::Exact = match_mode { "Exact" } else { "Suffix" },
            "description": description
        }),
        true,
    );

    // Persistence
    let encryption_key = state.encryption_key;
    save_authorized_patterns(&rules.authorized_patterns, &encryption_key)
        .context("Failed to save authorized patterns")?;

    info!("✅ Authorized pattern: {:?} ({:?})", pattern, match_mode);
    Ok(format!("OK: Authorized pattern: {}\n", pattern.join(",")))
}

pub async fn handle_list_auth(state: &Arc<AppState>) -> Result<String> {
    let rules = state.rules.read().unwrap();
    let json = serde_json::to_string(&rules.authorized_patterns)?;
    Ok(format!("OK: {}\n", json))
}

pub async fn handle_revoke(state: &Arc<AppState>, cmd: &str, caller_uid: u32) -> Result<String> {
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

    let pattern_parts: Vec<String> = pattern_str
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let mut rules = state.rules.write().unwrap();
    let initial_len = rules.authorized_patterns.len();

    rules
        .authorized_patterns
        .retain(|p| p.pattern != pattern_parts || p.match_mode != match_mode);

    if rules.authorized_patterns.len() < initial_len {
        let patterns = rules.authorized_patterns.clone();

        let crate::state::RulesState {
            ref mut auth_exact_cache,
            ref mut auth_suffix_cache,
            ..
        } = *rules;
        rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);

        let username = get_username_from_uid(caller_uid);
        let _ = state.logger.log_audit(
            "REVOKE",
            &username,
            serde_json::json!({ "pattern": pattern_parts.join(","), "mode": mode_str }),
            true,
        );

        let encryption_key = state.encryption_key;
        save_authorized_patterns(&rules.authorized_patterns, &encryption_key)?;

        info!(
            "🗑️ Revoked pattern: {} ({})",
            pattern_parts.join(","),
            mode_str
        );
        Ok(format!(
            "OK: Revoked pattern: {}\n",
            pattern_parts.join(",")
        ))
    } else {
        Ok("ERROR: NOT_FOUND: Pattern not found\n".to_string())
    }
}
pub async fn handle_clear(state: &Arc<AppState>, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Authorization requires root privileges\n".to_string());
    }

    let mut rules = state.rules.write().unwrap();
    rules.authorized_patterns.clear();
    let patterns = rules.authorized_patterns.clone();

    let crate::state::RulesState {
        ref mut auth_exact_cache,
        ref mut auth_suffix_cache,
        ..
    } = *rules;
    rebuild_auth_caches(&patterns, auth_exact_cache, auth_suffix_cache);

    let username = get_username_from_uid(caller_uid);
    let _ = state.logger.log_audit(
        "CLEAR_AUTHORIZATIONS",
        &username,
        serde_json::json!({ "reason": "user_request" }),
        true,
    );

    let encryption_key = state.encryption_key;
    save_authorized_patterns(&rules.authorized_patterns, &encryption_key)?;

    info!("🗑️ Cleared all authorized patterns");
    Ok("OK: All patterns cleared\n".to_string())
}
