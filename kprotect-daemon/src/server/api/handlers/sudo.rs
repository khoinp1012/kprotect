use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use log::{info, warn};
use crate::state::AppState;
use crate::core::process::build_lineage_chain;
use kprotect_common::{SudoRule, LogEntry};
use super::super::utils::{save_sudo_rules, get_username_from_uid};

pub async fn handle_check_sudo(state: &Arc<Mutex<AppState>>, cmd: &str) -> Result<String> {
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

    let result = {
        let (mut chain, is_complete, path_found) = {
            let state_lock = state.lock().await;
            let lineage_cache = state_lock.lineage_cache.clone();
            
            let maybe_path = lineage_cache.get(&target_pid).map(|n| n.path.clone());

            if let Some(path) = maybe_path {
                let (chain, complete) = build_lineage_chain(target_pid, &"".to_string(), &path, &lineage_cache);
                (chain, complete, true)
            } else {
                (vec![format!("PID:{}", target_pid)], false, false)
            }
        };

        if let Some(cmd) = target_cmd {
            chain.push(cmd);
        }

        if !path_found {
            warn!("🛑 PRIVILEGE GUARD: Sudo check for PID {} denied: PID not in cache", target_pid);
            broadcast_elevation_event(state, target_pid, &chain, "Blocked Elevation", false, "PID not in lineage cache", false).await;
            return Ok("DENY: PID not found in lineage cache\n".to_string());
        }

        if !is_complete {
            warn!("⚠️ Sudo check for PID {} denied: Incomplete lineage chain: ({})", 
                   target_pid, chain.join(" -> "));
            broadcast_elevation_event(state, target_pid, &chain, "Blocked Elevation", false, "Incomplete lineage chain", false).await;
            return Ok("DENY: Incomplete lineage chain\n".to_string());
        }

        // Check rules (locking state)
        let (matched, rule_desc) = {
            let state_lock = state.lock().await;
            let mut m = false;
            let mut d = String::new();
            for rule in &state_lock.sudo_rules {
                if !rule.enabled { continue; }
                if rule.pattern == chain {
                    m = true;
                    d = rule.description.clone();
                    break;
                }
            }
            (m, d)
        };

        if matched {
            info!("🔓 PRIVILEGE GUARD: Sudo authorized for PID {} ({}) - Rule: {}", 
                   target_pid, chain.join(" -> "), rule_desc);
            
            // Log audit asynchronously
            {
                let state_lock = state.lock().await;
                let username = get_username_from_uid(0); 
                let _ = state_lock.logger.log_audit(
                    "SUDO_BYPASS",
                    &username,
                    serde_json::json!({
                        "pid": target_pid,
                        "chain": chain,
                        "rule": rule_desc
                    }),
                    true
                );
            }

            broadcast_elevation_event(state, target_pid, &chain, "Elevation", true, &rule_desc, true).await;
            Ok("OK: Authorized\n".to_string())
        } else {
            warn!("🛑 PRIVILEGE GUARD: Sudo DENIED for PID {} ({})", target_pid, chain.join(" -> "));
            broadcast_elevation_event(state, target_pid, &chain, "Blocked Elevation", false, "No matching rule", true).await;
            Ok("DENY: No matching privilege rule found\n".to_string())
        }
    };
    result
}

async fn broadcast_elevation_event(
    state: &Arc<Mutex<AppState>>, 
    pid: u32, 
    chain: &[String], 
    status: &str, 
    authorized: bool,
    details: &str,
    complete: bool
) {
    let mut state_lock = state.lock().await;
    
    // Increment event sequence
    state_lock.event_sequence += 1;
    let event_id = state_lock.event_sequence;

    let target_cmd = chain.last().cloned().unwrap_or_else(|| "unknown".to_string());

    let entry = LogEntry::SecurityEvent {
        id: event_id,
        timestamp: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        status: status.to_string(),
        pid,
        comm: target_cmd.clone(), // Use target command as comm/process name
        target: "Sudo Bypass".to_string(),
        chain: chain.to_vec(),
        signature: "N/A".to_string(),
        authorized,
        complete,
        label_snapshot: vec![details.to_string()],
    };

    // Log to file
    if let Err(e) = state_lock.logger.log_entry(&entry) {
        warn!("Failed to log sudo event: {}", e);
    } else {
        info!("📝 Sudo event persisted: ID {}", event_id);
    }

    let event_msg = serde_json::to_string(&entry).unwrap_or_default();
    let _ = state_lock.event_tx.send(event_msg.clone());
    
    // Trigger Notifications
    let nm = state_lock.notification_manager.clone();
    drop(state_lock);

    let ev_type = if authorized {
        kprotect_common::EventTypeFilter::SudoVerified
    } else {
        kprotect_common::EventTypeFilter::SudoBlocked
    };

    // Use the last element of the chain (target command) as the "path" for matching
    let event_json: serde_json::Value = serde_json::from_str(&event_msg).unwrap_or_default();

    nm.match_and_dispatch(ev_type, &target_cmd, event_json).await;
}

pub async fn handle_sudo_add(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Sudo rule modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 3 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SUDO_ADD;<pattern_comma_sep>;<description>\n".to_string());
    }

    let pattern: Vec<String> = parts[1].split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let description = parts[2].trim().to_string();

    let rule = SudoRule {
        pattern,
        description,
        created_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
        enabled: true,
    };

    {
        let mut state_lock = state.lock().await;
        state_lock.sudo_rules.push(rule);
        
        let encryption_key = state_lock.encryption_key.clone();
        save_sudo_rules(&state_lock.sudo_rules, &encryption_key)?;
    }

    Ok("OK: Sudo rule added\n".to_string())
}

pub async fn handle_sudo_remove(state: &Arc<Mutex<AppState>>, cmd: &str, caller_uid: u32) -> Result<String> {
    if caller_uid != 0 {
        return Ok("ERROR: PERMISSION: Sudo rule modification requires root privileges\n".to_string());
    }

    let parts: Vec<&str> = cmd.split(';').collect();
    if parts.len() < 2 {
        return Ok("ERROR: INVALID_SYNTAX: Usage: SUDO_REMOVE;<pattern_comma_sep>\n".to_string());
    }

    let pattern: Vec<String> = parts[1].split(',')
        .map(|s| s.trim().to_string())
        .collect();

    let mut found = false;
    {
        let mut state_lock = state.lock().await;
        if let Some(pos) = state_lock.sudo_rules.iter().position(|r| r.pattern == pattern) {
            state_lock.sudo_rules.remove(pos);
            found = true;
            
            let encryption_key = state_lock.encryption_key.clone();
            save_sudo_rules(&state_lock.sudo_rules, &encryption_key)?;
        }
    }

    if found {
        Ok("OK: Sudo rule removed\n".to_string())
    } else {
        Ok("ERROR: Rule not found\n".to_string())
    }
}

pub async fn handle_sudo_list(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let state_lock = state.lock().await;
    let json = serde_json::to_string(&state_lock.sudo_rules)?;
    Ok(format!("OK: {}\n", json))
}
