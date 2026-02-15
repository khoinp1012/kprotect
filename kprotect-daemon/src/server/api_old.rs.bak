use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::Mutex;
use tokio::net::UnixStream;
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufReader, AsyncBufReadExt};
use std::ffi::CString;
use std::collections::HashMap;
use log::{info, warn, error};
use serde_json::json;
use sha2::{Sha256, Digest};

use crate::state::AppState;
use kprotect_common::{MatchMode, AuthorizedPattern, NotificationRule, SystemStats, ResourceUsage, ZoneStats};
use crate::core::auth::{rebuild_auth_caches, insert_prefix, remove_prefix, insert_suffix, remove_suffix, parse_pattern};
use crate::core::domain::{PatternType, ChainTrieNode};
use crate::crypto;
use crate::migration::{self, ZonesFile};
use crate::config::{self, DaemonConfig};
use crate::notifications;
use crate::logger;

// Constants for file paths (duplicated from main.rs references ideally constant in config/constants)
const ZONES_ENC: &str = "/var/lib/kprotect/configs/zones.enc";
const ENRICHMENT_ENC: &str = "/var/lib/kprotect/configs/enrichment.enc";
const AUTHORIZED_PATTERNS_PATH: &str = "/var/lib/kprotect/configs/authorized_patterns.enc";
const NOTIFICATION_RULES_PATH: &str = "/var/lib/kprotect/configs/notifications.enc";
const SOCKET_PATH: &str = "/run/kprotect/kprotect.sock";
const MAX_RED_ZONE_PATTERNS: usize = 192;
const MAX_AUTH_SIGNATURES: usize = 1024;
const MAX_ENRICHMENT_PATTERNS: usize = 32;
const MAX_ZONE_PER_TYPE: usize = 64;

pub async fn handle_client(mut stream: UnixStream, state: Arc<Mutex<AppState>>) -> Result<()> {
    // SECURITY: Identify the caller ONCE at connection start
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
            // Broadcast events to client (for TUI/GUI streaming)
            Ok(event_msg) = rx.recv(), if is_subscribed => {
                // Forward event to client
                if writer.write_all(event_msg.as_bytes()).await.is_err() {
                    break; // Client disconnected
                }
                if writer.write_all(b"\n").await.is_err() {
                    break;
                }
            }
            
            // Receive commands from client (Line-based)
            n = reader.read_line(&mut line) => {
                let n = n?;
                if n == 0 { break; } // EOF
                
                let cmd = line.trim().to_string(); // Clone to own string
                line.clear(); // Clear buffer for next read
                
                // Permission levels
                let is_root = caller_uid == 0;
                let is_kprotect_member = is_user_in_group(caller_uid, "kprotect");
                let has_audit_access = is_root || is_kprotect_member;

                // ========== PROTOCOL HANDLER ==========
                
                // AUTHORIZE <pattern> <mode> [description]
                if cmd.starts_with("AUTHORIZE") {
                    if caller_uid != 0 {
                        warn!("🚨 Security Alert: Non-root user (UID={}) tried to authorize a pattern!", caller_uid);
                        let _ = writer.write_all(b"ERROR: PERMISSION: Authorization requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    
                    if parts.len() < 3 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: AUTHORIZE;<pattern>;<mode>;[description]\n").await;
                        continue;
                    }
                    
                    let pattern: Vec<String> = parts[1].split(',')
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
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Cannot authorize an empty process chain (No chain detected)\n").await;
                        continue;
                    }
                    
                    let match_mode = match parts[2].trim() {
                        "Exact" => MatchMode::Exact,
                        "Suffix" => MatchMode::Suffix,
                        _ => {
                            let _ = writer.write_all(b"ERROR: INVALID_MODE: Use 'Exact' or 'Suffix'\n").await;
                            continue;
                        }
                    };
                    
                    let description = if parts.len() > 3 { parts[3].trim().to_string() } else { String::new() };
                    
                    // Create authorized pattern object
                    let auth_pattern = AuthorizedPattern {
                        pattern: pattern.clone(),
                        match_mode: match_mode.clone(),
                        description: description.clone(),
                        authorized_at: std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs(),
                    };
                    
                    // Update State
                    {
                        let mut state_lock = state.lock().await;
                        
                        // Add to list
                        state_lock.authorized_patterns.push(auth_pattern.clone());
                        
                        // Rebuild optimization caches
                        {
                            let state = &mut *state_lock;
                            rebuild_auth_caches(&state.authorized_patterns, &mut state.auth_exact_cache, &mut state.auth_suffix_cache);
                        }
                        
                        // Log audit trail
                        let username = get_username_from_uid(caller_uid);
                        let mode_display = match match_mode {
                            MatchMode::Exact => "Exact",
                            MatchMode::Suffix => "Suffix",
                        };
                        
                        let _ = state_lock.logger.log_audit(
                            "AUTHORIZE",
                            &username,
                            serde_json::json!({
                                "pattern": pattern.join(","),
                                "mode": mode_display,
                                "description": description
                            }),
                            true
                        );

                        // Phase 7: Persistence
                        if let Err(e) = save_authorized_patterns(&state_lock.authorized_patterns, &state_lock.encryption_key) {
                             error!("Failed to save authorized patterns: {}", e);
                        }
                    }

                    info!("✅ Authorized pattern: {:?} ({:?})", pattern, match_mode);
                    let _ = writer.write_all(format!("OK: Authorized pattern: {}\n", pattern.join(",")).as_bytes()).await;
                }
                
                // REVOKE_PATTERN;<pattern>;<mode>
                else if cmd.starts_with("REVOKE_PATTERN") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Revocation requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() < 3 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: REVOKE_PATTERN;<pattern>;<mode>\n").await;
                        continue;
                    }

                    let pattern_parts: Vec<String> = parts[1].split(',')
                        .map(|s| s.trim().to_string())
                        .collect();
                    
                    let match_mode = match parts[2].trim() {
                        "Exact" => MatchMode::Exact,
                        "Suffix" => MatchMode::Suffix,
                        _ => {
                            let _ = writer.write_all(b"ERROR: INVALID_MODE: Use 'Exact' or 'Suffix'\n").await;
                            continue;
                        }
                    };

                    let mut state_lock = state.lock().await;
                    
                    // Find and remove the matching pattern
                    let initial_len = state_lock.authorized_patterns.len();
                    state_lock.authorized_patterns.retain(|p| 
                        p.pattern != pattern_parts || p.match_mode != match_mode
                    );

                    if state_lock.authorized_patterns.len() < initial_len {
                        // Rebuild optimization caches
                        {
                            let st = &mut *state_lock;
                            rebuild_auth_caches(&st.authorized_patterns, &mut st.auth_exact_cache, &mut st.auth_suffix_cache);
                        }
                        // Log audit trail
                        let username = get_username_from_uid(caller_uid);
                        let _ = state_lock.logger.log_audit(
                            "REVOKE",
                            &username,
                            serde_json::json!({
                                "pattern": pattern_parts,
                                "mode": parts[2].trim(),
                            }),
                            true
                        );
                        
                        info!("✅ Pattern revoked by {}: {:?}", username, pattern_parts);
                        
                        // Phase 7: Persistence
                        if let Err(e) = save_authorized_patterns(&state_lock.authorized_patterns, &state_lock.encryption_key) {
                            error!("Failed to save authorized patterns after revocation: {}", e);
                        }
                        
                        // Clear kernel map
                        info!("扫 Clearing kernel authorization map...");
                        let mut auth_map_lock = state_lock.auth_map.lock().await;
                        let mut keys_to_remove = Vec::new();
                        for key_result in auth_map_lock.keys() {
                            if let Ok(key) = key_result {
                                keys_to_remove.push(key);
                            }
                        }
                        for key in keys_to_remove {
                            let _ = auth_map_lock.remove(&key);
                        }
                        
                        let _ = writer.write_all(b"OK: Pattern revoked\n").await;
                    } else {
                        let _ = writer.write_all(b"ERROR: NOT_FOUND: No matching pattern found\n").await;
                    }
                }
                
                // CLEAR
                else if cmd == "CLEAR" {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Authorization requires root privileges\n").await;
                        continue;
                    }
                    info!("扫 Clearing all authorized patterns");
                    
                    {
                        let mut state_lock = state.lock().await;
                        state_lock.authorized_patterns.clear();
                        
                        // Rebuild optimization caches
                        {
                            let st = &mut *state_lock;
                            rebuild_auth_caches(&st.authorized_patterns, &mut st.auth_exact_cache, &mut st.auth_suffix_cache);
                        }
                        
                        // Phase 7: Persistence
                        if let Err(e) = save_authorized_patterns(&state_lock.authorized_patterns, &state_lock.encryption_key) {
                            error!("Failed to save authorized patterns after clearing: {}", e);
                        }
                        
                        // Log audit trail
                        let username = get_username_from_uid(caller_uid);
                        let _ = state_lock.logger.log_audit(
                            "CLEAR",
                            &username,
                            serde_json::json!({ "action": "clear_all_patterns" }),
                            true
                        );
                        
                        // Clear the kernel map
                        let mut auth_map_lock = state_lock.auth_map.lock().await;
                        let mut keys_to_remove = Vec::new();
                        for key_result in auth_map_lock.keys() {
                            if let Ok(key) = key_result {
                                keys_to_remove.push(key);
                            }
                        }
                        for key in keys_to_remove {
                            let _ = auth_map_lock.remove(&key);
                        }
                    } // All locks dropped
                    
                    let _ = writer.write_all(b"OK: Cleared all patterns\n").await;
                }
                
                // LIST_PATTERNS - Return all authorized patterns
                else if cmd == "LIST_PATTERNS" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing patterns requires kprotect group or root\n").await;
                        continue;
                    }
                    
                    let response = {
                        let state_lock = state.lock().await;
                        let patterns = &state_lock.authorized_patterns;
                        
                        // Serialize patterns to JSON
                        let json = serde_json::to_string(patterns)
                            .unwrap_or_else(|_| "[]".to_string());
                        format!("OK: {}\n", json)
                    }; // state_lock dropped here
                    
                    let _ = writer.write_all(response.as_bytes()).await;
                }
                
                // ZONE_ADD;<zone_type>;<pattern>
                else if cmd.starts_with("ZONE_ADD;") {
                    if caller_uid != 0 {
                        warn!("🚨 Security Alert: Non-root user (UID={}) tried to add a zone!", caller_uid);
                        let _ = writer.write_all(b"ERROR: PERMISSION: Zone modification requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() < 3 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: ZONE_ADD;<zone_type>;<pattern>\n").await;
                        continue;
                    }

                    let zone_type = parts[1].trim();
                    let pattern_str = parts[2].trim();

                    // Validate zone type
                    if zone_type != "red" {
                        let _ = writer.write_all(b"ERROR: INVALID_ZONE_TYPE: Only 'red' zones are currently supported\n").await;
                        continue;
                    }

                    if pattern_str.is_empty() {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Pattern cannot be empty\n").await;
                        continue;
                    }

                    // Get encryption key
                    let key = {
                        let state_lock = state.lock().await;
                        state_lock.encryption_key.clone()
                    };

                    match add_zone_to_file(pattern_str, &key).await {
                        Ok(p) => {
                            // Hot-load into eBPF Map
                            if let Ok(pattern_type) = parse_pattern(&p) {
                                let mut state_lock = state.lock().await;
                                match pattern_type {
                                    PatternType::Prefix(ref p_str) => {
                                        let mut map = state_lock.red_prefix.lock().await;
                                        if let Err(e) = insert_prefix(&mut *map, p_str) {
                                            warn!("Failed to hot-load zone to eBPF map: {}", e);
                                        }
                                    },
                                    PatternType::Suffix(ref s_str) => {
                                        let mut map = state_lock.red_suffix.lock().await;
                                        if let Err(e) = insert_suffix(&mut *map, s_str) {
                                            warn!("Failed to hot-load zone to eBPF map: {}", e);
                                        }
                                    },
                                    PatternType::Exact(ref e_str) => {
                                        let mut map = state_lock.red_exact.lock().await;
                                        let hash = fnv1a_hash(e_str.as_bytes());
                                        if let Err(e) = map.insert(hash, 1, 0) {
                                            warn!("Failed to hot-load zone to eBPF map: {}", e);
                                        }
                                    }
                                }

                                let username = get_username_from_uid(caller_uid);
                                let _ = state_lock.logger.log_audit(
                                    "ZONE_ADD",
                                    &username,
                                    serde_json::json!({ "pattern": &p, "zone_type": zone_type }),
                                    true
                                );
                                info!("✅ Zone added by {}: {} (type: {})", username, p, zone_type);
                            }
                            let _ = writer.write_all(format!("OK: Zone added: {}\n", p).as_bytes()).await;
                        },
                        Err(e) => {
                            let response = format!("ERROR: FAILED_TO_ADD_ZONE: {}\n", e);
                            let _ = writer.write_all(response.as_bytes()).await;
                        }
                    }
                }

                // ZONE_REMOVE;<zone_type>;<pattern>
                else if cmd.starts_with("ZONE_REMOVE;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Zone modification requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() < 3 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: ZONE_REMOVE;<zone_type>;<pattern>\n").await;
                        continue;
                    }

                    let zone_type = parts[1].trim();
                    let pattern_str = parts[2].trim();

                    // Validate zone type
                    if zone_type != "red" {
                        let _ = writer.write_all(b"ERROR: INVALID_ZONE_TYPE: Only 'red' zones are currently supported\n").await;
                        continue;
                    }

                    let key = {
                        let state_lock = state.lock().await;
                        state_lock.encryption_key.clone()
                    };

                    match remove_zone_from_file(pattern_str, &key).await {
                        Ok(true) => {
                            // Hot-remove from eBPF Map
                            if let Ok(pattern_type) = parse_pattern(pattern_str) {
                                let mut state_lock = state.lock().await;
                                match pattern_type {
                                    PatternType::Prefix(ref p_str) => {
                                        let mut map = state_lock.red_prefix.lock().await;
                                        let _ = remove_prefix(&mut *map, p_str);
                                    },
                                    PatternType::Suffix(ref s_str) => {
                                        let mut map = state_lock.red_suffix.lock().await;
                                        let _ = remove_suffix(&mut *map, s_str);
                                    },
                                    PatternType::Exact(ref e_str) => {
                                        let mut map = state_lock.red_exact.lock().await;
                                        let hash = fnv1a_hash(e_str.as_bytes());
                                        let _ = map.remove(&hash);
                                    }
                                }

                                let username = get_username_from_uid(caller_uid);
                                let _ = state_lock.logger.log_audit(
                                    "ZONE_REMOVE",
                                    &username,
                                    serde_json::json!({ "pattern": pattern_str, "zone_type": zone_type }),
                                    true
                                );
                                info!("✅ Zone removed by {}: {} (type: {})", username, pattern_str, zone_type);
                            }
                            let _ = writer.write_all(b"OK: Zone removed\n").await;
                        },
                        Ok(false) => {
                            let _ = writer.write_all(b"ERROR: NOT_FOUND: Zone not found\n").await;
                        },
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // ZONE_LIST
                else if cmd == "ZONE_LIST" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing zones requires kprotect group or root\n").await;
                        continue;
                    }
                    let key = {
                        let state_lock = state.lock().await;
                        state_lock.encryption_key.clone()
                    };
                    match read_zones_file(&key).await {
                        Ok(zones) => {
                            let json = serde_json::to_string(&zones).unwrap_or_default();
                            let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                        }
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // PATTERN_ADD;<pattern>
                else if cmd.starts_with("PATTERN_ADD;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Pattern management requires root privileges\n").await;
                        continue;
                    }
                    let parts: Vec<&str> = cmd.splitn(2, ';').collect();
                    if parts.len() == 2 {
                        let pattern = parts[1].trim();
                        let (key, patterns_map) = {
                            let state_lock = state.lock().await;
                            (state_lock.encryption_key.clone(), state_lock.red_enrichment_prefix.clone())
                        };
                        match add_enrichment_pattern_to_file(pattern, &key).await {
                            Ok(_) => {
                                // Hot-load
                                if let Ok(PatternType::Prefix(p)) = parse_pattern(pattern) {
                                    let mut map = patterns_map.lock().await;
                                    let _ = insert_prefix(&mut *map, &p);
                                }
                                let username = get_username_from_uid(caller_uid);
                                let mut state_lock = state.lock().await;
                                let _ = state_lock.logger.log_audit(
                                    "PATTERN_ADD",
                                    &username,
                                    serde_json::json!({ "pattern": pattern, "type": "enrichment" }),
                                    true
                                );
                                let _ = writer.write_all(b"OK: Pattern added and applied\n").await;
                            },
                            Err(e) => {
                                let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                            }
                        }
                    }
                }

                // PATTERN_REMOVE;<pattern>
                else if cmd.starts_with("PATTERN_REMOVE;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Pattern management requires root privileges\n").await;
                        continue;
                    }
                    let parts: Vec<&str> = cmd.splitn(2, ';').collect();
                    if parts.len() == 2 {
                        let pattern = parts[1].trim();
                        let (key, patterns_map) = {
                            let state_lock = state.lock().await;
                            (state_lock.encryption_key.clone(), state_lock.red_enrichment_prefix.clone())
                        };
                        match remove_enrichment_pattern_from_file(pattern, &key).await {
                            Ok(true) => {
                                // Hot-remove
                                if let Ok(PatternType::Prefix(p)) = parse_pattern(pattern) {
                                    let mut map = patterns_map.lock().await;
                                    let _ = remove_prefix(&mut *map, &p);
                                }
                                let username = get_username_from_uid(caller_uid);
                                let mut state_lock = state.lock().await;
                                let _ = state_lock.logger.log_audit(
                                    "PATTERN_REMOVE",
                                    &username,
                                    serde_json::json!({ "pattern": pattern, "type": "enrichment" }),
                                    true
                                );
                                let _ = writer.write_all(b"OK: Pattern removed and applied\n").await;
                            },
                            Ok(false) => {
                                let _ = writer.write_all(b"ERROR: NOT_FOUND: Pattern not found\n").await;
                            }
                            Err(e) => {
                                let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                            }
                        }
                    }
                }

                // PATTERN_LIST
                else if cmd == "PATTERN_LIST" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing patterns requires kprotect group or root\n").await;
                        continue;
                    }
                    let key = {
                        let state_lock = state.lock().await;
                        state_lock.encryption_key.clone()
                    };
                    match read_enrichment_patterns_file(&key).await {
                        Ok(patterns) => {
                            let config = crate::core::domain::EnrichmentFile { enrichment_patterns: patterns };
                            let json = serde_json::to_string(&config).unwrap_or_default();
                            let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                        }
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // GET_LOG_CONFIG
                else if cmd == "GET_LOG_CONFIG" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing config requires kprotect group or root\n").await;
                        continue;
                    }
                    let state_lock = state.lock().await;
                    let config_lock = state_lock.config.lock().await;
                    let json = serde_json::to_string(&*config_lock).unwrap_or_default();
                    let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                }

                // SET_LOG_RETENTION;event_days;audit_days
                else if cmd.starts_with("SET_LOG_RETENTION;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Log configuration requires root privileges\n").await;
                        continue;
                    }
                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() == 3 {
                        if let (Ok(event_days), Ok(audit_days)) = (parts[1].parse::<u32>(), parts[2].parse::<u32>()) {
                            let state_lock = state.lock().await;
                            let mut config_lock = state_lock.config.lock().await;
                            config_lock.event_log_retention_days = event_days;
                            config_lock.audit_log_retention_days = audit_days;
                            let key = state_lock.encryption_key.clone();
                            if let Ok(_) = crate::config::save_config(&*config_lock, &key) {
                                let username = get_username_from_uid(caller_uid);
                                let _ = state_lock.logger.log_audit(
                                    "SET_LOG_RETENTION",
                                    &username,
                                    serde_json::json!({ "event_days": event_days, "audit_days": audit_days }),
                                    true
                                );
                                let _ = writer.write_all(b"OK: Log retention updated\n").await;
                            } else {
                                let _ = writer.write_all(b"ERROR: FAILED_SAVE\n").await;
                            }
                        }
                    }
                }

                // GET_EVENTS;count;offset
                else if cmd.starts_with("GET_EVENTS;") {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing events requires kprotect group or root\n").await;
                        continue;
                    }
                    let parts: Vec<&str> = cmd.split(';').collect();
                    let count = parts.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
                    let offset = parts.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    let state_lock = state.lock().await;
                    match state_lock.logger.read_events(count, offset) {
                        Ok(events) => {
                            let json = serde_json::to_string(&events).unwrap_or_else(|_| "[]".to_string());
                            let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                        }
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // GET_AUDIT;count;offset
                else if cmd.starts_with("GET_AUDIT;") {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing audit logs requires kprotect group or root\n").await;
                        continue;
                    }
                    let parts: Vec<&str> = cmd.split(';').collect();
                    let count = parts.get(1).and_then(|s| s.parse::<usize>().ok()).unwrap_or(50);
                    let offset = parts.get(2).and_then(|s| s.parse::<usize>().ok()).unwrap_or(0);
                    let state_lock = state.lock().await;
                    match state_lock.logger.read_audit(count, offset) {
                        Ok(entries) => {
                            let json = serde_json::to_string(&entries).unwrap_or_else(|_| "[]".to_string());
                            let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                        }
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // LIST_NOTIFY_RULES
                else if cmd == "LIST_NOTIFY_RULES" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing notifications requires kprotect group or root\n").await;
                        continue;
                    }
                    let state_lock = state.lock().await;
                    let rules = state_lock.notification_manager.get_rules().await;
                    let json = serde_json::to_string(&rules).unwrap_or_else(|_| "[]".to_string());
                    let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                }

                // GET_STATS - Return resource usage (current/max)
                else if cmd == "GET_STATS" {
                    if !has_audit_access {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Viewing stats requires kprotect group or root\n").await;
                        continue;
                    }
                    
                    let stats = {
                        let state_lock = state.lock().await;
                        
                        // 1. Authorized Chains
                        let auth_current = state_lock.authorized_patterns.len();
                        
                        // 2. Zones (Break down by parsing the patterns in the file)
                        let mut exact_count = 0;
                        let mut prefix_count = 0;
                        let mut suffix_count = 0;
                        
                        let zones_file: Result<ZonesFile> = crate::crypto::load_encrypted(ZONES_ENC, &state_lock.encryption_key);
                        if let Ok(zf) = zones_file {
                            for pattern in zf.red_zones {
                                match parse_pattern(&pattern) {
                                    Ok(PatternType::Exact(_)) => exact_count += 1,
                                    Ok(PatternType::Prefix(_)) => prefix_count += 1,
                                    Ok(PatternType::Suffix(_)) => suffix_count += 1,
                                    _ => {}
                                }
                            }
                        }
                        
                        // 3. Enrichment
                        let mut enrichment_count = 0;
                        let enrichment_file: Result<Vec<String>> = crate::crypto::load_encrypted(ENRICHMENT_ENC, &state_lock.encryption_key);
                        if let Ok(ef) = enrichment_file {
                            enrichment_count = ef.len();
                        }
                        
                        SystemStats {
                            authorized_chains: ResourceUsage { current: auth_current, max: MAX_AUTH_SIGNATURES },
                            enrichment: ResourceUsage { current: enrichment_count, max: MAX_ENRICHMENT_PATTERNS },
                            zones: ZoneStats {
                                exact: ResourceUsage { current: exact_count, max: MAX_ZONE_PER_TYPE },
                                prefix: ResourceUsage { current: prefix_count, max: MAX_ZONE_PER_TYPE },
                                suffix: ResourceUsage { current: suffix_count, max: MAX_ZONE_PER_TYPE },
                            },
                        }
                    };
                    
                    let json = serde_json::to_string(&stats).unwrap_or_default();
                    let _ = writer.write_all(format!("OK: {}\n", json).as_bytes()).await;
                }

                // ADD_NOTIFY_RULE;name;event_types;path_pattern;action_type;destination;timeout
                else if cmd.starts_with("ADD_NOTIFY_RULE;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Notification management requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() != 7 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: ADD_NOTIFY_RULE;name;event_types;path_pattern;action_type;destination;timeout\n").await;
                        continue;
                    }

                    let name = parts[1].to_string();
                    let event_types_raw: Vec<&str> = parts[2].split(',').collect();
                    let mut event_types = Vec::new();
                    for et in event_types_raw {
                        match et.trim() {
                            "Verified" => event_types.push(kprotect_common::EventTypeFilter::Verified),
                            "Blocked" => event_types.push(kprotect_common::EventTypeFilter::Blocked),
                            _ => {
                                let _ = writer.write_all(format!("ERROR: INVALID_EVENT_TYPE: {}\n", et).as_bytes()).await;
                                continue;
                            }
                        }
                    }

                    let path_pattern = if parts[3].is_empty() || parts[3] == "null" { None } else { Some(parts[3].to_string()) };
                    let action_type = match parts[4] {
                        "Script" => kprotect_common::ActionType::Script,
                        "Webhook" => kprotect_common::ActionType::Webhook,
                        _ => {
                            let _ = writer.write_all(b"ERROR: INVALID_ACTION_TYPE: Use 'Script' or 'Webhook'\n").await;
                            continue;
                        }
                    };
                    let destination = parts[5].to_string();
                    let timeout = parts[6].parse::<u32>().unwrap_or(30);

                    let rule = kprotect_common::NotificationRule {
                        id: 0, // Assigned by manager
                        name: name.clone(),
                        enabled: true,
                        event_types,
                        path_pattern,
                        action_type,
                        destination,
                        timeout,
                        created_at: 0, // Assigned by manager
                        last_triggered: None,
                        trigger_count: 0,
                        success_count: 0,
                        failure_count: 0,
                        timeout_count: 0,
                        total_execution_ms: 0,
                    };

                    let state_lock = state.lock().await;
                    match state_lock.notification_manager.add_rule(rule).await {
                        Ok(id) => {
                            let rules = state_lock.notification_manager.get_rules().await;
                            if let Err(e) = save_notification_rules(&rules, &state_lock.encryption_key) {
                                error!("Failed to save notification rules: {}", e);
                            }
                            
                            // Log audit
                            let username = get_username_from_uid(caller_uid);
                            let _ = state_lock.logger.log_audit(
                                "ADD_NOTIFY_RULE",
                                &username,
                                serde_json::json!({ "id": id, "name": name }),
                                true
                            );
                            let _ = writer.write_all(format!("OK: {}\n", id).as_bytes()).await;
                        }
                        Err(e) => {
                            let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                        }
                    }
                }

                // REMOVE_NOTIFY_RULE;id
                else if cmd.starts_with("REMOVE_NOTIFY_RULE;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Notification management requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() != 2 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: REMOVE_NOTIFY_RULE;id\n").await;
                        continue;
                    }

                    if let Ok(id) = parts[1].parse::<u32>() {
                        let state_lock = state.lock().await;
                        match state_lock.notification_manager.remove_rule(id).await {
                            Ok(_) => {
                                let rules = state_lock.notification_manager.get_rules().await;
                                let _ = save_notification_rules(&rules, &state_lock.encryption_key);
                                
                                // Log audit
                                let username = get_username_from_uid(caller_uid);
                                let _ = state_lock.logger.log_audit(
                                    "REMOVE_NOTIFY_RULE",
                                    &username,
                                    serde_json::json!({ "id": id }),
                                    true
                                );
                                let _ = writer.write_all(b"OK: Rule removed\n").await;
                            }
                            Err(e) => {
                                let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                            }
                        }
                    } else {
                        let _ = writer.write_all(b"ERROR: INVALID_ID\n").await;
                    }
                }

                // TOGGLE_NOTIFY_RULE;id;enabled
                else if cmd.starts_with("TOGGLE_NOTIFY_RULE;") {
                    if caller_uid != 0 {
                        let _ = writer.write_all(b"ERROR: PERMISSION: Notification management requires root privileges\n").await;
                        continue;
                    }

                    let parts: Vec<&str> = cmd.split(';').collect();
                    if parts.len() != 3 {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Usage: TOGGLE_NOTIFY_RULE;id;true/false\n").await;
                        continue;
                    }

                    if let (Ok(id), Ok(enabled)) = (parts[1].parse::<u32>(), parts[2].parse::<bool>()) {
                        let state_lock = state.lock().await;
                        match state_lock.notification_manager.toggle_rule(id, enabled).await {
                            Ok(_) => {
                                let rules = state_lock.notification_manager.get_rules().await;
                                let _ = save_notification_rules(&rules, &state_lock.encryption_key);
                                
                                // Log audit
                                let username = get_username_from_uid(caller_uid);
                                let _ = state_lock.logger.log_audit(
                                    "TOGGLE_NOTIFY_RULE",
                                    &username,
                                    serde_json::json!({ "id": id, "enabled": enabled }),
                                    true
                                );
                                let _ = writer.write_all(b"OK: Rule updated\n").await;
                            }
                            Err(e) => {
                                let _ = writer.write_all(format!("ERROR: FAILED: {}\n", e).as_bytes()).await;
                            }
                        }
                    } else {
                        let _ = writer.write_all(b"ERROR: INVALID_PARAMETERS\n").await;
                    }
                }

                // STATS
                else if cmd == "STATS" {
                    let response = {
                        let state_lock = state.lock().await;
                        let stats = serde_json::json!({
                            "daemon": {
                                "version": "0.1.0",
                                "uptime_seconds": state_lock.start_time.elapsed().as_secs(),
                                "ebpf_loaded": true
                            },
                            "patterns": {
                                "authorized": state_lock.authorized_patterns.len(),
                                "total_processes": state_lock.lineage_cache.len()
                            },
                            "events": {
                                "verified": state_lock.events_verified,
                                "blocked": state_lock.events_blocked
                            }
                        });
                        format!("OK: {}\n", stats)
                    };
                    let _ = writer.write_all(response.as_bytes()).await;
                }
                
                // INSPECT <signature>
                else if cmd.starts_with("INSPECT ") {
                    let sig_str = cmd.strip_prefix("INSPECT ").unwrap();
                    if let Ok(s) = u64::from_str_radix(sig_str.trim_start_matches("0x"), 16) {
                        let response_opt = {
                            let state_lock = state.lock().await;
                            state_lock.lineage_cache.values()
                                .find(|node| node.signature == s)
                                .map(|node| {
                                    let info = serde_json::json!({
                                        "signature": format!("0x{:x}", s),
                                        "lineage": { "path": node.path, "arg": node.arg, "ppid": node.ppid }
                                    });
                                    format!("OK: {}\n", info)
                                })
                        };
                        if let Some(response) = response_opt {
                            let _ = writer.write_all(response.as_bytes()).await;
                        } else {
                            let _ = writer.write_all(b"ERROR: NOT_FOUND: Signature not found\n").await;
                        }
                    } else {
                        let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Invalid signature format\n").await;
                    }
                }
                
                // PING
                else if cmd == "PING" {
                    let _ = writer.write_all(b"OK: PONG\n").await;
                }
                
                // VERSION
                else if cmd == "VERSION" {
                    let _ = writer.write_all(b"OK: kprotect v0.1.0 (protocol v1.0)\n").await;
                }

                // STATUS
                else if cmd == "STATUS" {
                    let response = {
                        let state_lock = state.lock().await;
                        let uptime_seconds = state_lock.start_time.elapsed().as_secs();
                        
                        let status = serde_json::json!({
                            "uptime_seconds": uptime_seconds,
                            "ebpf_loaded": true,
                            "active_connections": 1,
                            "socket_path": SOCKET_PATH
                        });
                        format!("OK: {}\n", status)
                    };
                    let _ = writer.write_all(response.as_bytes()).await;
                }
                
                // ENCRYPTION_INFO - Encryption status and metadata
                else if cmd == "ENCRYPTION_INFO" {
                    let response = {
                        let state_lock = state.lock().await;
                        let key = &state_lock.encryption_key;
                        
                        // Generate key fingerprint
                        let mut hasher = Sha256::new();
                        hasher.update(key);
                        let hash_result = hasher.finalize();
                        let fingerprint = format!("{:x}", hash_result);
                        let key_fingerprint = format!("{}...{}", &fingerprint[..8], &fingerprint[fingerprint.len()-8..]);
                        
                        // Get policy file metadata
                        let mut policy_files = Vec::new();
                        for path in ["/var/lib/kprotect/configs/zones.enc", 
                                     "/var/lib/kprotect/configs/authorized_patterns.enc",
                                     "/var/lib/kprotect/configs/enrichment.enc"] {
                            if let Ok(metadata) = std::fs::metadata(path) {
                                if let Ok(modified) = metadata.modified() {
                                    if let Ok(duration) = modified.duration_since(std::time::UNIX_EPOCH) {
                                        policy_files.push(serde_json::json!({
                                            "path": path,
                                            "last_modified": duration.as_secs()
                                        }));
                                    }
                                }
                            }
                        }
                        
                        let encryption_info = serde_json::json!({
                            "enabled": true,
                            "algorithm": "AES-256-GCM",
                            "key_fingerprint": key_fingerprint,
                            "policy_files": policy_files
                        });
                        format!("OK: {}\n", encryption_info)
                    };
                    let _ = writer.write_all(response.as_bytes()).await;
                }
                
                // SYSTEM_INFO - Policy statistics and eBPF maps
                else if cmd == "SYSTEM_INFO" {
                    let response = {
                        let state_lock = state.lock().await;
                        
                        let authorized_patterns = state_lock.authorized_patterns.len();
                        
                        let (red_zones, enrichment_patterns) = {
                            let red_count = tokio::task::block_in_place(|| {
                                let zones: Result<crate::migration::ZonesFile> = crate::crypto::load_encrypted(ZONES_ENC, &state_lock.encryption_key);
                                zones.map(|z| z.red_zones.len()).unwrap_or(0)
                            });
                            let enrich_count = tokio::task::block_in_place(|| {
                                let patterns: Result<Vec<String>> = crate::crypto::load_encrypted(ENRICHMENT_ENC, &state_lock.encryption_key);
                                patterns.map(|p| p.len()).unwrap_or(0)
                            });
                            
                            (red_count, enrich_count)
                        };
                        
                        let process_cache_size = state_lock.lineage_cache.len();
                        let events_verified = state_lock.events_verified;
                        let events_blocked = state_lock.events_blocked;
                        
                        let system_info = serde_json::json!({
                            "authorized_patterns": authorized_patterns, 
                            "red_zones": red_zones,
                            "enrichment_patterns": enrichment_patterns,
                            "events_verified": events_verified,
                            "events_blocked": events_blocked,
                            "lineage_cache_size": process_cache_size,
                            "event_log_size_bytes": std::fs::metadata("/var/log/kprotect/events.jsonl.enc").map(|m| m.len()).unwrap_or(0),
                            "audit_log_size_bytes": std::fs::metadata("/var/log/kprotect/audit.jsonl.enc").map(|m| m.len()).unwrap_or(0),
                            "ebpf_maps": {
                                "process_signatures": {
                                    "size": process_cache_size,
                                    "capacity": 8192
                                },
                                "authorized_signatures": {
                                    "size": authorized_patterns,
                                    "capacity": 1024
                                }
                            }
                        });
                        format!("OK: {}\n", system_info)
                    };
                    let _ = writer.write_all(response.as_bytes()).await;
                }
                
                // CAPABILITIES
                else if cmd == "CAPABILITIES" {
                    let caps = serde_json::json!({
                        "version": env!("CARGO_PKG_VERSION"),
                        "protocol_version": "1.0",
                        "features": ["encryption", "argument_enrichment", "zone_management", "event_streaming"],
                        "permissions": {
                            "current_user": if caller_uid == 0 { "root" } else { "user" },
                            "can_authorize": caller_uid == 0,
                            "can_revoke": caller_uid == 0,
                            "can_modify_zones": caller_uid == 0
                        },
                        "resources": ["authorized_signatures", "zones", "enrichment_patterns", "events", "statistics"]
                    });
                    let _ = writer.write_all(format!("OK: {}\n", caps).as_bytes()).await;
                }
                
                // SCHEMA <resource>
                else if cmd.starts_with("SCHEMA ") {
                    let resource = cmd.strip_prefix("SCHEMA ").unwrap().trim();
                    let schema = match resource {
                        "authorized_signatures" => serde_json::json!({
                            "resource": "authorized_signatures",
                            "description": "Process lineage signatures authorized for red zone access",
                            "fields": [
                                { "name": "signature", "type": "hex_u64", "required": true, "pattern": "^0x[0-9a-fA-F]+$", "description": "Unique hash of process ancestry chain", "display_name": "Signature Hash" },
                                { "name": "description", "type": "string", "required": false, "max_length": 256, "description": "Human-readable description of the workflow", "display_name": "Description" }
                            ]
                        }),
                        "zones" => serde_json::json!({
                            "resource": "zones",
                            "description": "Red and green zones for file access control",
                            "fields": [
                                { "name": "pattern", "type": "string", "required": true, "description": "File path pattern (supports * wildcard)", "display_name": "Path Pattern" },
                                { "name": "type", "type": "enum", "values": ["red"], "description": "Zone type (always red)", "display_name": "Zone Type" }
                            ]
                        }),
                        _ => serde_json::json!({ "error": "NOT_FOUND", "message": format!("Unknown resource: {}", resource) })
                    };
                    let _ = writer.write_all(format!("OK: {}\n", schema).as_bytes()).await;
                }
                
                // SUBSCRIBE
                else if cmd == "SUBSCRIBE" {
                    is_subscribed = true;
                    let _ = writer.write_all(b"OK: Subscribed to live events\n").await;
                }
                
                // HELP
                else if cmd == "HELP" {
                    let help_text = "OK: Available commands: AUTHORIZE, REVOKE_PATTERN, CLEAR, LIST_PATTERNS, ZONE_ADD, ZONE_REMOVE, ZONE_LIST, PATTERN_ADD, PATTERN_REMOVE, PATTERN_LIST, GET_LOG_CONFIG, SET_LOG_RETENTION, GET_EVENTS, GET_AUDIT, LIST_NOTIFY_RULES, ADD_NOTIFY_RULE, REMOVE_NOTIFY_RULE, TOGGLE_NOTIFY_RULE, STATS, INSPECT, PING, VERSION, STATUS, ENCRYPTION_INFO, SYSTEM_INFO, CAPABILITIES, SCHEMA, SUBSCRIBE, HELP\n";
                    let _ = writer.write_all(help_text.as_bytes()).await;
                }
                
                else if !cmd.is_empty() {
                    let _ = writer.write_all(b"ERROR: INVALID_SYNTAX: Unknown command (type HELP for list)\n").await;
                }
            }
        }
    }
    Ok(())
}

// Helpers

/// Get username from UID
fn get_username_from_uid(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            if let Ok(name_str) = std::ffi::CStr::from_ptr((*pw).pw_name).to_str() {
                return name_str.to_string();
            }
        }
    }
    format!("{}", uid)
}

/// Check if a user (UID) belongs to a specific group name
fn is_user_in_group(uid: u32, group_name: &str) -> bool {
    // Root is always allowed
    if uid == 0 { return true; }

    let uid_nix = nix::unistd::Uid::from_raw(uid);
    let user = match nix::unistd::User::from_uid(uid_nix) {
        Ok(Some(u)) => u,
        _ => return false,
    };

    let target_gid = match nix::unistd::Group::from_name(group_name) {
        Ok(Some(g)) => g.gid,
        _ => return false,
    };

    // Check primary group
    if user.gid == target_gid {
        return true;
    }

    // Check supplementary groups
    let user_name_c = match CString::new(user.name) {
        Ok(s) => s,
        Err(_) => return false,
    };

    if let Ok(groups) = nix::unistd::getgrouplist(&user_name_c, user.gid) {
        for gid in groups {
            if gid == target_gid {
                return true;
            }
        }
    }
    
    false 
}

/// Save authorized patterns to encrypted storage (Phase 7)
fn save_authorized_patterns(patterns: &Vec<AuthorizedPattern>, key: &[u8; 32]) -> Result<()> {
    crypto::save_encrypted(patterns, AUTHORIZED_PATTERNS_PATH, key)
        .context("Failed to save authorized patterns")
}

async fn read_zones_file(key: &[u8; 32]) -> Result<ZonesFile> {
    tokio::task::block_in_place(|| {
        crypto::load_encrypted(ZONES_ENC, key)
            .context("Failed to load encrypted zones")
    })
}

async fn add_zone_to_file(pattern: &str, key: &[u8; 32]) -> Result<String> {
    let mut zones = read_zones_file(key).await?;
    
    // VALIDATE FIRST - ensure pattern is valid before truncation
    let _ = parse_pattern(pattern)
        .context("Invalid pattern: asterisk must be at start or end only, not in the middle")?;
    
    // THEN truncate (Daemon is the single source of truth)
    let final_pattern = truncate_zone_pattern(pattern);
    
    // Check if already exists
    if zones.red_zones.contains(&final_pattern) {
        anyhow::bail!("Pattern already exists");
    }
    
    // Check limit for red zones
    if zones.red_zones.len() >= MAX_RED_ZONE_PATTERNS {
        anyhow::bail!("Red zone limit reached ({} patterns max)", MAX_RED_ZONE_PATTERNS);
    }
    
    zones.red_zones.push(final_pattern.clone());
    
    // Write back to encrypted file
    tokio::task::block_in_place(|| {
        crypto::save_encrypted(&zones, ZONES_ENC, key)
    })?;
    
    Ok(final_pattern)
}

async fn remove_zone_from_file(pattern: &str, key: &[u8; 32]) -> Result<bool> {
    let mut zones = read_zones_file(key).await?;
    
    let initial_len = zones.red_zones.len();
    zones.red_zones.retain(|p| p != pattern);
    
    if zones.red_zones.len() == initial_len {
        return Ok(false); // Not found
    }
    
    // Write back to encrypted file
    tokio::task::block_in_place(|| {
        crypto::save_encrypted(&zones, ZONES_ENC, key)
    })?;
    
    Ok(true)
}

async fn read_enrichment_patterns_file(key: &[u8; 32]) -> Result<Vec<String>> {
    tokio::task::block_in_place(|| {
        crypto::load_encrypted(ENRICHMENT_ENC, key)
            .context("Failed to load encrypted enrichment patterns")
    })
}

async fn add_enrichment_pattern_to_file(pattern: &str, key: &[u8; 32]) -> Result<()> {
    let mut patterns = read_enrichment_patterns_file(key).await?;
    
    // Check if already exists
    if patterns.contains(&pattern.to_string()) {
        anyhow::bail!("Pattern already exists");
    }
    
    // VALIDATE FIRST - before adding to the list
    // Validation: Must end with * (Prefix pattern)
    if !pattern.ends_with('*') {
        anyhow::bail!("Enrichment pattern must end with '*' (e.g. /usr/bin/python*)");
    }

    // Check invalid * usage (e.g. * in middle or start)
    match parse_pattern(pattern) {
        Ok(PatternType::Prefix(_)) => {},
        _ => anyhow::bail!("Enrichment pattern must be a valid prefix pattern (* at end only)"),
    }
    
    // THEN add to the list
    patterns.push(pattern.to_string());
    
    // Write back to encrypted file
    tokio::task::block_in_place(|| {
        crypto::save_encrypted(&patterns, ENRICHMENT_ENC, key)
    })?;
    
    Ok(())
}

async fn remove_enrichment_pattern_from_file(pattern: &str, key: &[u8; 32]) -> Result<bool> {
    let mut patterns = read_enrichment_patterns_file(key).await?;
    
    let initial_len = patterns.len();
    patterns.retain(|p| p != pattern);
    
    if patterns.len() == initial_len {
        return Ok(false); // Not found
    }
    
    // Write back to encrypted file
    tokio::task::block_in_place(|| {
        crypto::save_encrypted(&patterns, ENRICHMENT_ENC, key)
    })?;
    
    Ok(true)
}

fn save_notification_rules(rules: &Vec<kprotect_common::NotificationRule>, key: &[u8; 32]) -> Result<()> {
    crypto::save_encrypted(rules, NOTIFICATION_RULES_PATH, key)
        .context("Failed to save notification rules")
}

// ... other helpers
fn truncate_zone_pattern(pattern: &str) -> String {
    crate::core::auth::truncate_zone_pattern(pattern)
}

fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        if b == 0 { break; }
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}


