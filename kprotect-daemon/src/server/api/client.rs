use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::UnixStream;
use tokio::io::{AsyncWriteExt, BufReader, AsyncBufReadExt};

use crate::state::AppState;
use super::handlers::*;

pub async fn handle_client(stream: UnixStream, state: Arc<Mutex<AppState>>) -> Result<()> {
    let peer_creds = stream.peer_cred()?;
    let caller_uid = peer_creds.uid();

    let mut is_subscribed = false;
    let mut rx = {
        let state_lock = state.lock().await;
        state_lock.event_tx.subscribe()
    };

    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        tokio::select! {
            n = reader.read_line(&mut line) => {
                let n = n?;
                if n == 0 { break; } 
                
                let cmd = line.trim().to_string();
                line.clear();
                
                if cmd.is_empty() { continue; }

                let response = match cmd.as_str() {
                    // Auth Handlers
                    c if c.starts_with("AUTHORIZE") => auth::handle_authorize(&state, c, caller_uid).await?,
                    "LIST_PATTERNS" => auth::handle_list_auth(&state).await?,
                    c if c.starts_with("REVOKE_PATTERN") => auth::handle_revoke(&state, c, caller_uid).await?,
                    
                    // Zone Handlers
                    c if c.starts_with("ZONE_ADD") => rules::handle_zone_add(&state, c, caller_uid).await?,
                    c if c.starts_with("ZONE_REMOVE") => rules::handle_zone_remove(&state, c, caller_uid).await?,
                    "ZONE_LIST" => rules::handle_zone_list(&state).await?,
                    
                    // Enrichment Handlers
                    c if c.starts_with("PATTERN_ADD") => rules::handle_pattern_add(&state, c, caller_uid).await?,
                    c if c.starts_with("PATTERN_REMOVE") => rules::handle_pattern_remove(&state, c, caller_uid).await?,
                    "PATTERN_LIST" => rules::handle_pattern_list(&state).await?,

                    // Metrics & System Handlers
                    "STATS" | "GET_STATS" => metrics::handle_stats(&state).await?,
                    "STATUS" => metrics::handle_status(&state).await?,
                    "SYSTEM_INFO" => metrics::handle_system_info(&state).await?,
                    "CAPABILITIES" => metrics::handle_capabilities(&state).await?,
                    "ENCRYPTION_INFO" => metrics::handle_encryption_info(&state).await?,
                    "GET_LOG_CONFIG" => metrics::handle_get_log_config(&state).await?,
                    
                    // Notification Handlers
                    "LIST_NOTIFY_RULES" => notifications::handle_notify_list(&state).await?,
                    c if c.starts_with("ADD_NOTIFY_RULE") => notifications::handle_notify_add(&state, c, caller_uid).await?,
                    c if c.starts_with("REMOVE_NOTIFY_RULE") => notifications::handle_notify_remove(&state, c, caller_uid).await?,
                    c if c.starts_with("TOGGLE_NOTIFY_RULE") => notifications::handle_notify_toggle(&state, c, caller_uid).await?,

                    // Logs Handlers
                    c if c.starts_with("GET_EVENTS") => {
                        let parts: Vec<&str> = c.split(';').collect();
                        let count = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
                        let offset = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        metrics::handle_get_events(&state, count, offset).await?
                    },
                    c if c.starts_with("GET_AUDIT") => {
                        let parts: Vec<&str> = c.split(';').collect();
                        let count = parts.get(1).and_then(|s| s.parse().ok()).unwrap_or(50);
                        let offset = parts.get(2).and_then(|s| s.parse().ok()).unwrap_or(0);
                        metrics::handle_get_audit(&state, count, offset).await?
                    },

                    // Process Handlers
                    c if c.starts_with("INSPECT ") => {
                        let sig_str = c.strip_prefix("INSPECT ").unwrap();
                        if let Ok(s) = u64::from_str_radix(sig_str.trim_start_matches("0x"), 16) {
                            match process::handle_inspect(&state, s).await? {
                                Some(resp) => resp,
                                None => "ERROR: NOT_FOUND: Signature not found\n".to_string(),
                            }
                        } else {
                            "ERROR: INVALID_SYNTAX: Invalid signature format\n".to_string()
                        }
                    },
                    
                    // Sudo Bypass Handlers
                    c if c.starts_with("CHECK_SUDO ") => sudo::handle_check_sudo(&state, c).await?,
                    c if c.starts_with("SUDO_ADD") => sudo::handle_sudo_add(&state, c, caller_uid).await?,
                    c if c.starts_with("SUDO_REMOVE") => sudo::handle_sudo_remove(&state, c, caller_uid).await?,
                    "SUDO_LIST" => sudo::handle_sudo_list(&state).await?,

                    // Basic Handlers
                    "PING" => "OK: PONG\n".to_string(),
                    "VERSION" => "OK: kprotect v0.1.0 (protocol v1.0)\n".to_string(),
                    "SUBSCRIBE" => {
                        is_subscribed = true;
                        "OK: Subscribed to live events (batched)\n".to_string()
                    },
                    "HELP" => "OK: Available commands: AUTHORIZE, LIST_PATTERNS, REVOKE_PATTERN, ZONE_ADD, ZONE_REMOVE, ZONE_LIST, PATTERN_ADD, PATTERN_REMOVE, PATTERN_LIST, STATS, STATUS, SYSTEM_INFO, ENCRYPTION_INFO, GET_LOG_CONFIG, GET_EVENTS, GET_AUDIT, INSPECT, CHECK_SUDO, SUDO_ADD, SUDO_LIST, PING, VERSION, SUBSCRIBE, HELP\n".to_string(),
                    _ => "ERROR: INVALID_SYNTAX: Unknown command (type HELP for list)\n".to_string(),
                };

                let _ = writer.write_all(response.as_bytes()).await;
            }

            // Batched Event Streaming (100ms intervals)
            _ = tokio::time::sleep(std::time::Duration::from_millis(100)), if is_subscribed => {
                let mut batch = Vec::new();
                while let Ok(event_msg) = rx.try_recv() {
                    batch.push(event_msg);
                    if batch.len() >= 50 { break; }
                }
                
                if !batch.is_empty() {
                    let batched_msg = batch.join("\n") + "\n";
                    if writer.write_all(batched_msg.as_bytes()).await.is_err() { break; }
                }
            }
        }
    }
    Ok(())
}
