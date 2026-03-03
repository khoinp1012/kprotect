use super::super::utils::{get_username_from_uid, save_sudo_rules};
use crate::core::process::build_lineage_chain;
use crate::state::AppState;
use anyhow::Result;
use kprotect_common::{LogEntry, SudoRule};
use log::{info, warn};
use std::sync::Arc;

use std::sync::atomic::Ordering;

pub async fn handle_check_sudo(state: &Arc<AppState>, cmd: &str) -> Result<String> {
    check_sudo_internal(state, cmd).await
}

async fn check_sudo_internal(state: &Arc<AppState>, cmd: &str) -> Result<String> {
    let parts: Vec<&str> = cmd.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok("DENY: Missing PID\n".to_string());
    }

    let target_pid: u32 = match parts[1].trim().parse() {
        Ok(p) => p,
        Err(_) => return Ok("DENY: Invalid PID\n".to_string()),
    };

    let target_cmd = if parts.len() > 2 {
        Some(parts[2..].join(" "))
    } else {
        None
    };

    let (mut chain, is_complete, path_found) = {
        let lineage_cache = state.lineage_cache.clone();
        let maybe_path = lineage_cache.get(&target_pid).map(|n| n.path.clone());
        if let Some(path) = maybe_path {
            let (chain, complete) =
                build_lineage_chain(target_pid, "", &path, &lineage_cache);
            (chain, complete, true)
        } else {
            (vec![format!("PID:{}", target_pid)], false, false)
        }
    };

    if let Some(cmd) = target_cmd {
        chain.push(cmd);
    }

    let (_engine_enabled, _sudo_bypass_enabled, sudo_rules) = {
        let rules = state.rules.read().unwrap();
        (
            rules.config.engine_enabled,
            rules.config.sudo_bypass_enabled,
            rules.sudo_rules.clone(),
        )
    };

    evaluate_sudo_access(
        state,
        target_pid,
        &chain,
        path_found,
        is_complete,
        &sudo_rules,
    )
    .await
}

enum SudoVerdict {
    Authorized(String),
    Ignored(String, String),  // (User message, Log Reason)
    Standard(String, String), // (User message, Log Reason) - Show in feed but proceed to standard auth
    #[allow(dead_code)]
    Denied(String, String), // (User message, Log/Event reason)
}

async fn evaluate_sudo_access(
    state: &Arc<AppState>,
    target_pid: u32,
    chain: &[String],
    path_found: bool,
    is_complete: bool,
    sudo_rules: &[SudoRule],
) -> Result<String> {
    let (engine_enabled, sudo_bypass_enabled) = {
        let rules = state.rules.read().unwrap();
        (rules.config.engine_enabled, rules.config.sudo_bypass_enabled)
    };
    let verdict = evaluate_sudo_access_logic(
        target_pid,
        chain,
        path_found,
        is_complete,
        engine_enabled,
        sudo_bypass_enabled,
        sudo_rules,
    )
    .await;

    match verdict {
        SudoVerdict::Authorized(rule_desc) => {
            info!(
                "🔓 PRIVILEGE GUARD: Sudo authorized for PID {} ({}) - Rule: {}",
                target_pid,
                chain.join(" -> "),
                rule_desc
            );

            let username = get_username_from_uid(0);
            let _ = state.logger.log_audit(
                "SUDO_BYPASS",
                &username,
                serde_json::json!({ "pid": target_pid, "chain": chain, "rule": rule_desc }),
                true,
            );

            broadcast_elevation_event(
                state,
                target_pid,
                chain,
                "Elevation",
                true,
                &rule_desc,
                true,
            )
            .await;
            state.sudo_events_verified.fetch_add(1, Ordering::SeqCst);
            state.last_pam_elevations.insert(
                target_pid,
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
            );
            Ok("OK: Authorized\n".to_string())
        }
        SudoVerdict::Ignored(user_msg, log_reason) => {
            // For IGNORE, we don't block, but we might log an INFO or WARN depending on reason
            if log_reason == "Engine disabled" {
                warn!(
                    "⚠️ PRIVILEGE GUARD: Sudo check for PID {} IGNORED: Engine disabled",
                    target_pid
                );
            } else if log_reason == "Sudo Bypass disabled" {
                // Silent ignore for bypass disabled
            }

            Ok(format!("IGNORE: {}\n", user_msg))
        }
        SudoVerdict::Standard(user_msg, log_reason) => {
            // Standard sudo attempt: not authorized for bypass, but not explicitly denied.
            // We broadcast this so it shows up in the UI "Live Feed" as an authorizeable event.
            broadcast_elevation_event(
                state,
                target_pid,
                chain,
                "Standard Elevation",
                false,
                &log_reason,
                is_complete,
            )
            .await;
            Ok(format!("IGNORE: {}\n", user_msg))
        }
        SudoVerdict::Denied(user_msg, log_reason) => {
            if log_reason == "Engine disabled" {
                warn!(
                    "🚫 PRIVILEGE GUARD: Sudo check for PID {} denied: Engine is disabled",
                    target_pid
                );
            } else if log_reason == "Sudo Bypass disabled" {
                warn!(
                    "🚫 PRIVILEGE GUARD: Sudo check for PID {} denied: Sudo Bypass is disabled",
                    target_pid
                );
            } else if log_reason == "PID not in lineage cache" {
                warn!(
                    "🛑 PRIVILEGE GUARD: Sudo check for PID {} denied: PID not in cache",
                    target_pid
                );
            } else if log_reason == "Incomplete lineage chain" {
                warn!(
                    "⚠️ Sudo check for PID {} denied: Incomplete lineage chain: ({})",
                    target_pid,
                    chain.join(" -> ")
                );
            } else {
                warn!(
                    "🛑 PRIVILEGE GUARD: Sudo DENIED for PID {} ({}) - Reason: {}",
                    target_pid,
                    chain.join(" -> "),
                    log_reason
                );
            }

            broadcast_elevation_event(
                state,
                target_pid,
                chain,
                "Blocked Elevation",
                false,
                &log_reason,
                is_complete,
            )
            .await;
            state.sudo_events_blocked.fetch_add(1, Ordering::SeqCst);
            Ok(user_msg)
        }
    }
}
async fn evaluate_sudo_access_logic(
    _target_pid: u32,
    chain: &[String],
    path_found: bool,
    is_complete: bool,
    engine_enabled: bool,
    sudo_bypass_enabled: bool,
    sudo_rules: &[SudoRule],
) -> SudoVerdict {
    if !engine_enabled {
        return SudoVerdict::Ignored("Engine disabled".to_string(), "Engine disabled".to_string());
    }
    if !sudo_bypass_enabled {
        return SudoVerdict::Ignored(
            "Sudo Bypass disabled".to_string(),
            "Sudo Bypass disabled".to_string(),
        );
    }

    if !path_found {
        // If PID not found, we can't verify lineage. SAFE DEFAULT: Allow standard sudo (IGNORE).
        return SudoVerdict::Ignored(
            "PID not found in lineage cache".to_string(),
            "PID not in lineage cache".to_string(),
        );
    }

    if !is_complete {
        // Incomplete chain.
        return SudoVerdict::Standard(
            "Incomplete lineage chain".to_string(),
            "Incomplete lineage chain".to_string(),
        );
    }

    for rule in sudo_rules {
        if !rule.enabled {
            continue;
        }

        if matches_sudo_rule(&rule.pattern, chain) {
            return SudoVerdict::Authorized(rule.description.clone());
        }
    }

    SudoVerdict::Standard(
        "No matching privilege rule found".to_string(),
        "No matching rule".to_string(),
    )
}

fn matches_sudo_rule(pattern: &[String], chain: &[String]) -> bool {
    if pattern.len() != chain.len() {
        return false;
    }

    for (p_part, c_part) in pattern.iter().zip(chain.iter()) {
        // Strip args from chain part if present: "/bin/bash [-bash]" -> "/bin/bash"
        let normalized_c = if let Some(idx) = c_part.find(" [") {
            &c_part[..idx]
        } else {
            c_part.as_str()
        };

        if p_part == normalized_c {
            continue;
        }

        return false;
    }

    true
}

async fn broadcast_elevation_event(
    state: &Arc<AppState>,
    pid: u32,
    chain: &[String],
    status: &str,
    authorized: bool,
    details: &str,
    complete: bool,
) {
    // Increment event sequence
    let event_id = state.event_sequence.fetch_add(1, Ordering::SeqCst) + 1;

    let target_cmd = chain
        .last()
        .cloned()
        .unwrap_or_else(|| "unknown".to_string());

    let entry = LogEntry::SecurityEvent {
        id: event_id,
        timestamp: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        status: status.to_string(),
        pid,
        comm: target_cmd.clone(), // Use target command as comm/process name
        target: target_cmd.clone(),
        chain: chain.to_vec(),
        signature: "N/A".to_string(),
        authorized,
        complete,
        label_snapshot: vec![details.to_string()],
    };

    // Log to file
    if let Err(e) = state.logger.log_entry(&entry) {
        warn!("Failed to log sudo event: {}", e);
    } else {
        info!("📝 Sudo event persisted: ID {}", event_id);
    }

    let event_msg = serde_json::to_string(&entry).unwrap_or_default();
    let _ = state.event_tx.send(event_msg.clone());

    // Trigger Notifications
    let nm = state.notification_manager.clone();

    let ev_type = if authorized {
        kprotect_common::EventTypeFilter::SudoVerified
    } else {
        kprotect_common::EventTypeFilter::SudoBlocked
    };

    // Use the last element of the chain (target command) as the "path" for matching
    let event_json: serde_json::Value = serde_json::from_str(&event_msg).unwrap_or_default();

    nm.match_and_dispatch(ev_type, &target_cmd, event_json)
        .await;
}

pub async fn handle_sudo_add(state: &Arc<AppState>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Sudo rule modification requires root privileges\n".to_string(),
        );
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok(
            "ERROR: INVALID_SYNTAX: Usage: SUDO_ADD;<pattern_comma_sep>;<description>\n"
                .to_string(),
        );
    }

    let pattern: Vec<String> = parts[1].split(',').map(|s| s.trim().to_string()).collect();

    let description = parts[2].trim().to_string();

    let rule = SudoRule {
        pattern,
        description,
        created_at: std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs(),
        enabled: true,
    };

    {
        let mut rules = state.rules.write().unwrap();
        rules.sudo_rules.push(rule);

        let encryption_key = state.encryption_key;
        save_sudo_rules(&rules.sudo_rules, &encryption_key)?;
    }

    Ok("OK: Sudo rule added\n".to_string())
}

pub async fn handle_sudo_remove(
    state: &Arc<AppState>,
    cmd: &str,
    caller_uid: u32,
) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Sudo rule modification requires root privileges\n".to_string(),
        );
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SUDO_REMOVE;<pattern_comma_sep>\n".to_string());
    }

    let pattern: Vec<String> = parts[1].split(',').map(|s| s.trim().to_string()).collect();

    let mut found = false;
    {
        let mut rules = state.rules.write().unwrap();
        if let Some(pos) = rules.sudo_rules.iter().position(|r| r.pattern == pattern) {
            rules.sudo_rules.remove(pos);
            found = true;

            let encryption_key = state.encryption_key;
            save_sudo_rules(&rules.sudo_rules, &encryption_key)?;
        }
    }

    if found {
        Ok("OK: Sudo rule removed\n".to_string())
    } else {
        Ok("ERROR: Rule not found\n".to_string())
    }
}

pub async fn handle_sudo_list(state: &Arc<AppState>) -> Result<String> {
    let rules = state.rules.read().unwrap();
    let json = serde_json::to_string(&rules.sudo_rules)?;
    Ok(format!("OK: {}\n", json))
}

pub async fn handle_sudo_clear(state: &Arc<AppState>, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok(
            "ERROR: PERMISSION: Sudo rule modification requires root privileges\n".to_string(),
        );
    }

    {
        let mut rules = state.rules.write().unwrap();
        rules.sudo_rules.clear();

        let encryption_key = state.encryption_key;
        save_sudo_rules(&rules.sudo_rules, &encryption_key)?;
    }

    info!("🗑️ Cleared all sudo rules");
    Ok("OK: All sudo rules cleared\n".to_string())
}


#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sudo_verdict_engine_disabled() {
        let rules = vec![];
        let verdict = evaluate_sudo_access_logic(
            1234,
            &["/bin/bash".into()],
            true,
            true,
            false,
            true,
            &rules,
        )
        .await;
        match verdict {
            SudoVerdict::Ignored(_, reason) => assert_eq!(reason, "Engine disabled"),
            _ => panic!("Should be ignored"),
        }
    }

    #[tokio::test]
    async fn test_sudo_verdict_incomplete_lineage() {
        let rules = vec![];
        // Path found but chain incomplete (e.g. parent missing)
        let verdict = evaluate_sudo_access_logic(
            1234,
            &["PID:100".into(), "/bin/bash".into()],
            true,
            false,
            true,
            true,
            &rules,
        )
        .await;
        match verdict {
            SudoVerdict::Ignored(_, reason) => assert_eq!(reason, "Incomplete lineage chain"),
            _ => panic!("Should be ignored"),
        }
    }

    #[tokio::test]
    async fn test_sudo_verdict_pid_not_found() {
        let rules = vec![];
        let verdict = evaluate_sudo_access_logic(
            1234,
            &["PID:1234".into()],
            false,
            false,
            true,
            true,
            &rules,
        )
        .await;
        match verdict {
            SudoVerdict::Ignored(_, reason) => assert_eq!(reason, "PID not in lineage cache"),
            _ => panic!("Should be ignored"),
        }
    }

    #[tokio::test]
    async fn test_sudo_verdict_authorized() {
        let rules = vec![SudoRule {
            pattern: vec!["/bin/bash".into(), "apt update".into()],
            description: "Allow apt".into(),
            created_at: 0,
            enabled: true,
        }];
        let verdict = evaluate_sudo_access_logic(
            1234,
            &["/bin/bash".into(), "apt update".into()],
            true,
            true,
            true,
            true,
            &rules,
        )
        .await;
        match verdict {
            SudoVerdict::Authorized(desc) => assert_eq!(desc, "Allow apt"),
            _ => panic!("Should be authorized"),
        }
    }

    // No incomplete tests placeholder needed

    #[tokio::test]
    async fn test_sudo_verdict_rule_disabled() {
        let rules = vec![SudoRule {
            pattern: vec!["/bin/bash".into()],
            description: "Allow bash".into(),
            created_at: 0,
            enabled: false,
        }];
        let verdict =
            evaluate_sudo_access_logic(1234, &["/bin/bash".into()], true, true, true, true, &rules)
                .await;
        match verdict {
            SudoVerdict::Ignored(_, reason) => assert_eq!(reason, "No matching rule"),
            _ => panic!("Should be ignored"),
        }
    }
}
