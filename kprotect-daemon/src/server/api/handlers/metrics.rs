use crate::state::AppState;
use anyhow::Result;
use serde_json::json;
use std::sync::atomic::Ordering;
use std::sync::Arc;

pub async fn handle_stats(state: &Arc<AppState>) -> Result<String> {
    let stats = {
        let rules = state.rules.read().unwrap();
        json!({
            "daemon": {
                "version": env!("CARGO_PKG_VERSION"),
                "uptime_seconds": state.start_time.elapsed().as_secs(),
                "ebpf_loaded": true
            },
            "patterns": {
                "authorized": rules.authorized_patterns.len(),
                "total_processes": state.lineage_cache.len()
            },
            "events": {
                "verified": state.events_verified.load(Ordering::SeqCst),
                "blocked": state.events_blocked.load(Ordering::SeqCst)
            }
        })
    };
    Ok(format!("OK: {}\n", stats))
}

pub async fn handle_system_info(state: &Arc<AppState>) -> Result<String> {
    let (
        authorized_patterns_count,
        sudo_rules_count,
        engine_enabled,
        file_protection_enabled,
        sudo_bypass_enabled,
    ) = {
        let rules_state = state.rules.read().unwrap();
        (
            rules_state.authorized_patterns.len(),
            rules_state.sudo_rules.len(),
            rules_state.config.engine_enabled,
            rules_state.config.file_protection_enabled,
            rules_state.config.sudo_bypass_enabled,
        )
    };

    let key = state.encryption_key;

    let (red_zones, enrichment_patterns) = {
        let red_count = crate::server::api::utils::read_zones_file(&key)
            .await
            .map(|z| z.red_zones.len())
            .unwrap_or(0);
        let enrich_count = crate::server::api::utils::read_enrichment_patterns_file(&key)
            .await
            .map(|p| p.len())
            .unwrap_or(0);
        (red_count, enrich_count)
    };

    let process_cache_size = state.lineage_cache.len();
    let events_verified = state.events_verified.load(Ordering::SeqCst);
    let events_blocked = state.events_blocked.load(Ordering::SeqCst);
    let sudo_events_verified = state.sudo_events_verified.load(Ordering::SeqCst);
    let sudo_events_blocked = state.sudo_events_blocked.load(Ordering::SeqCst);

    let system_info = build_system_info_json(SystemInfoParams {
        authorized_patterns: authorized_patterns_count,
        sudo_rules: sudo_rules_count,
        red_zones,
        enrichment_patterns,
        events_verified,
        events_blocked,
        sudo_events_verified,
        sudo_events_blocked,
        lineage_cache_size: process_cache_size,
        engine_enabled,
        file_protection_enabled,
        sudo_bypass_enabled,
    });

    Ok(format!("OK: {}\n", system_info))
}

pub struct SystemInfoParams {
    pub authorized_patterns: usize,
    pub sudo_rules: usize,
    pub red_zones: usize,
    pub enrichment_patterns: usize,
    pub events_verified: u64,
    pub events_blocked: u64,
    pub sudo_events_verified: u64,
    pub sudo_events_blocked: u64,
    pub lineage_cache_size: usize,
    pub engine_enabled: bool,
    pub file_protection_enabled: bool,
    pub sudo_bypass_enabled: bool,
}

pub fn build_system_info_json(params: SystemInfoParams) -> serde_json::Value {
    json!({
        "authorized_patterns": params.authorized_patterns,
        "sudo_rules_count": params.sudo_rules,
        "red_zones": params.red_zones,
        "enrichment_patterns": params.enrichment_patterns,
        "events_verified": params.events_verified,
        "events_blocked": params.events_blocked,
        "sudo_events_verified": params.sudo_events_verified,
        "sudo_events_blocked": params.sudo_events_blocked,
        "lineage_cache_size": params.lineage_cache_size,
        "event_log_size_bytes": std::fs::metadata("/var/log/kprotect/events.jsonl.enc").map(|m| m.len()).unwrap_or(0),
        "audit_log_size_bytes": std::fs::metadata("/var/log/kprotect/audit.jsonl.enc").map(|m| m.len()).unwrap_or(0),
        "ebpf_maps": {
            "process_signatures": {
                "size": params.lineage_cache_size,
                "capacity": 8192
            },
            "authorized_signatures": {
                "size": params.authorized_patterns,
                "capacity": 1024
            },
            "enrichment": {
                "size": params.enrichment_patterns,
                "capacity": 32
            }
        },
        "engine_enabled": params.engine_enabled,
        "file_protection_enabled": params.file_protection_enabled,
        "sudo_bypass_enabled": params.sudo_bypass_enabled,
    })
}

// Test module moved to end of file to satisfy Clippy lint.

pub async fn handle_status(state: &Arc<AppState>) -> Result<String> {
    let status = json!({
        "uptime_seconds": state.start_time.elapsed().as_secs(),
        "ebpf_loaded": true,
        "active_connections": 1, // Placeholder
        "socket_path": "/run/kprotect/kprotect.sock"
    });
    Ok(format!("OK: {}\n", status))
}

pub async fn handle_encryption_info(_state: &Arc<AppState>) -> Result<String> {
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

pub async fn handle_get_log_config(state: &Arc<AppState>) -> Result<String> {
    let config = {
        let rules = state.rules.read().unwrap();
        json!({
            "event_log_retention_days": rules.config.event_log_retention_days,
            "audit_log_retention_days": rules.config.audit_log_retention_days,
            "event_log_enabled": rules.config.event_log_enabled,
            "audit_log_enabled": rules.config.audit_log_enabled
        })
    };
    Ok(format!("OK: {}\n", config))
}

pub async fn handle_get_events(
    state: &Arc<AppState>,
    count: usize,
    offset: usize,
) -> Result<String> {
    let events = state.logger.read_events(count, offset)?;
    Ok(format!("OK: {}\n", serde_json::to_string(&events)?))
}

pub async fn handle_get_audit(
    state: &Arc<AppState>,
    count: usize,
    offset: usize,
) -> Result<String> {
    let audit = state.logger.read_audit(count, offset)?;
    Ok(format!("OK: {}\n", serde_json::to_string(&audit)?))
}

pub async fn handle_capabilities(_state: &Arc<AppState>) -> Result<String> {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_build_system_info_json_toggles() {
        let json = build_system_info_json(SystemInfoParams {
            authorized_patterns: 5,
            sudo_rules: 2,
            red_zones: 1,
            enrichment_patterns: 100,
            events_verified: 10,
            events_blocked: 50,
            sudo_events_verified: 0,
            sudo_events_blocked: 0,
            lineage_cache_size: 0,
            engine_enabled: true, // engine
            file_protection_enabled: false, // file protection
            sudo_bypass_enabled: true, // sudo bypass
        });

        assert_eq!(json["authorized_patterns"], 5);
        assert!(json["engine_enabled"].as_bool().unwrap());
        assert!(!json["file_protection_enabled"].as_bool().unwrap());
        assert!(json["sudo_bypass_enabled"].as_bool().unwrap());
        assert_eq!(json["events_verified"], 100);
        assert_eq!(json["events_blocked"], 10);
    }
}
