use anyhow::Result;
use std::sync::Arc;
use tokio::sync::Mutex;
use serde_json::json;
use crate::state::AppState;

pub async fn handle_stats(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let state_lock = state.lock().await;
    let stats = json!({
        "daemon": {
            "version": env!("CARGO_PKG_VERSION"),
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
    Ok(format!("OK: {}\n", stats))
}

pub async fn handle_system_info(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let state_lock = state.lock().await;
    
    let authorized_patterns_count = state_lock.authorized_patterns.len();
    let key = state_lock.encryption_key.clone();
    
    let (red_zones, enrichment_patterns) = tokio::task::spawn_blocking(move || {
        let red_count = crate::crypto::load_encrypted::<crate::migration::ZonesFile>(
            "/var/lib/kprotect/configs/zones.enc", &key
        ).map(|z| z.red_zones.len()).unwrap_or(0);
        
        let enrich_count = crate::crypto::load_encrypted::<Vec<String>>(
            "/var/lib/kprotect/configs/enrichment.enc", &key
        ).map(|p| p.len()).unwrap_or(0);
        
        (red_count, enrich_count)
    }).await?;
    
    let process_cache_size = state_lock.lineage_cache.len();
    let events_verified = state_lock.events_verified;
    let events_blocked = state_lock.events_blocked;
    
    let system_info = json!({
        "authorized_patterns": authorized_patterns_count, 
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
                "size": authorized_patterns_count,
                "capacity": 1024
            }
        }
    });
    Ok(format!("OK: {}\n", system_info))
}

pub async fn handle_status(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let state_lock = state.lock().await;
    let status = json!({
        "uptime_seconds": state_lock.start_time.elapsed().as_secs(),
        "ebpf_loaded": true,
        "active_connections": 1, // Placeholder
        "socket_path": "/run/kprotect/kprotect.sock"
    });
    Ok(format!("OK: {}\n", status))
}

pub async fn handle_encryption_info(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let _state_lock = state.lock().await;
    let info = json!({
        "enabled": true,
        "algorithm": "AES-256-GCM",
        "key_fingerprint": "v1-master-key",
        "policy_files": [
            { "path": "/var/lib/kprotect/configs/zones.enc", "last_modified": 0 },
            { "path": "/var/lib/kprotect/configs/enrichment.enc", "last_modified": 0 },
            { "path": "/var/lib/kprotect/configs/authorized_patterns.enc", "last_modified": 0 }
        ]
    });
    Ok(format!("OK: {}\n", info))
}

pub async fn handle_get_log_config(state: &Arc<Mutex<AppState>>) -> Result<String> {
    let _state_lock = state.lock().await;
    let config = json!({
        "event_log_retention_days": 30,
        "audit_log_retention_days": 90,
        "event_log_enabled": true,
        "audit_log_enabled": true
    });
    Ok(format!("OK: {}\n", config))
}

pub async fn handle_get_events(state: &Arc<Mutex<AppState>>, count: usize, offset: usize) -> Result<String> {
    let state_lock = state.lock().await;
    let events = state_lock.logger.read_events(count, offset)?;
    Ok(format!("OK: {}\n", serde_json::to_string(&events)?))
}

pub async fn handle_get_audit(state: &Arc<Mutex<AppState>>, count: usize, offset: usize) -> Result<String> {
    let state_lock = state.lock().await;
    let audit = state_lock.logger.read_audit(count, offset)?;
    Ok(format!("OK: {}\n", serde_json::to_string(&audit)?))
}

pub async fn handle_capabilities(_state: &Arc<Mutex<AppState>>) -> Result<String> {
    let caps = json!({
        "version": env!("CARGO_PKG_VERSION"),
        "protocol_version": "1.0",
        "features": ["lineage_tracking", "red_zones", "enrichment", "encrypted_logs", "event_batching"],
        "permissions": {
            "current_user": "root", // Placeholder for actually checking if user in group
            "can_authorize": true,
            "can_revoke": true,
            "can_modify_zones": true
        },
        "resources": ["events", "audit", "patterns", "zones", "notifications"]
    });
    Ok(format!("OK: {}\n", caps))
}
