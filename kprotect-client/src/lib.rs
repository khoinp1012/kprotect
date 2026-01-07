//! kprotect Client Library
//! 
//! Provides a clean Rust API for communicating with the kprotect daemon
//! via Unix socket protocol.

// kprotect-client: Client library for interacting with kprotect daemon
// Copyright (C) 2026 khoinp1012
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::UnixStream;

// Re-export common types
pub use kprotect_common::{MatchMode, LogEntry};

/// Client for communicating with kprotect daemon
#[derive(Clone)]
pub struct KprotectClient {
    socket_path: PathBuf,
}

impl KprotectClient {
    /// Create a new client with default socket path
    pub fn new() -> Self {
        Self {
            socket_path: PathBuf::from("/run/kprotect/kprotect.sock"),
        }
    }
    
    /// Create a new client with custom socket path
    pub fn with_socket_path(path: impl Into<PathBuf>) -> Self {
        Self {
            socket_path: path.into(),
        }
    }
    
    /// Send a command and get response
    async fn send_command(&self, command: &str) -> Result<String> {
        let mut stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to kprotect daemon")?;
        
        // Send command
        stream.write_all(command.as_bytes()).await?;
        stream.write_all(b"\n").await?;
        
        // Read response
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        
        Ok(response.trim().to_string())
    }
    
    /// Parse OK response and extract JSON
    fn parse_response(&self, response: &str) -> Result<String> {
        if let Some(json) = response.strip_prefix("OK: ") {
            Ok(json.to_string())
        } else if response.starts_with("ERROR:") {
            anyhow::bail!("Daemon error: {}", response)
        } else {
            anyhow::bail!("Unexpected response: {}", response)
        }
    }
    
    /// Get daemon capabilities
    pub async fn capabilities(&self) -> Result<Capabilities> {
        let response = self.send_command("CAPABILITIES").await?;
        let json = self.parse_response(&response)?;
        let caps = serde_json::from_str(&json)
            .context("Failed to parse capabilities")?;
        Ok(caps)
    }
    
    /// Get schema for a resource
    pub async fn schema(&self, resource: &str) -> Result<Schema> {
        let cmd = format!("SCHEMA {}", resource);
        let response = self.send_command(&cmd).await?;
        let json = self.parse_response(&response)?;
        let schema = serde_json::from_str(&json)
            .context("Failed to parse schema")?;
        Ok(schema)
    }
    
    // ...

    /// Authorize a lineage pattern
    /// 
    /// # Arguments
    /// * `pattern` - List of process paths (must include full paths)
    /// * `mode` - Match mode (Exact or Suffix)
    /// * `description` - Optional description
    pub async fn authorize_pattern(&self, pattern: &[String], mode: MatchMode, description: Option<&str>) -> Result<()> {
        let pattern_str = pattern.join(",");
        let mode_str = match mode {
            MatchMode::Exact => "Exact",
            MatchMode::Suffix => "Suffix",
        };
        
        let cmd = if let Some(desc) = description {
            format!("AUTHORIZE;{};{};{}", pattern_str, mode_str, desc)
        } else {
            format!("AUTHORIZE;{};{}", pattern_str, mode_str)
        };
        
        let response = self.send_command(&cmd).await?;
        if response.starts_with("OK:") {
            Ok(())
        } else {
            anyhow::bail!("Authorization failed: {}", response)
        }
    }

    /// Revoke a pattern by index
    pub async fn revoke_pattern(&self, pattern: Vec<String>, match_mode: MatchMode) -> Result<()> {
        let pattern_str = pattern.join(",");
        let mode_str = match match_mode {
            MatchMode::Exact => "Exact",
            MatchMode::Suffix => "Suffix",
        };
        let cmd = format!("REVOKE_PATTERN;{};{}", pattern_str, mode_str);
        let response = self.send_command(&cmd).await?;
        
        if response.starts_with("OK:") {
            Ok(())
        } else {
            anyhow::bail!("Revocation failed: {}", response)
        }
    }
    
    /// Get all authorized patterns
    pub async fn get_patterns(&self) -> Result<Vec<kprotect_common::AuthorizedPattern>> {
        let response = self.send_command("LIST_PATTERNS").await?;
        let json = self.parse_response(&response)?;
        let patterns = serde_json::from_str(&json)
            .context("Failed to parse patterns")?;
        Ok(patterns)
    }
    
    /// Deprecated: Authorize a signature (Use authorize_pattern instead)
    #[deprecated(note = "Use authorize_pattern instead")]
    pub async fn authorize(&self, _signature: u64, _description: Option<&str>) -> Result<()> {
        // Legacy support wrapper or fail
        anyhow::bail!("Hash-based authorization is deprecated. Please update your tools.")
    }
    
    /// Deprecated: Revoke a signature (Use revoke_pattern instead)
    #[deprecated(note = "Use revoke_pattern instead")]
    pub async fn revoke(&self, _signature: u64) -> Result<()> {
        anyhow::bail!("Hash-based revocation is deprecated. Please update your tools.")
    }
    
    /// Ping daemon
    pub async fn ping(&self) -> Result<String> {
        let response = self.send_command("PING").await?;
        Ok(response)
    }
    
    /// Get daemon version
    pub async fn version(&self) -> Result<String> {
        let response = self.send_command("VERSION").await?;
        Ok(response)
    }
    
    /// Subscribe to live events
    pub async fn subscribe(&self, stream: &mut UnixStream) -> Result<()> {
        stream.write_all(b"SUBSCRIBE\n").await?;
        let mut reader = BufReader::new(stream);
        let mut response = String::new();
        reader.read_line(&mut response).await?;
        if response.starts_with("OK:") {
            Ok(())
        } else {
            anyhow::bail!("Subscription failed: {}", response)
        }
    }

    /// Stream events from daemon (maintains persistent connection)
    /// Returns a UnixStream that continuously receives JSON event messages
    pub async fn stream_events(&self) -> Result<UnixStream> {
        let stream = UnixStream::connect(&self.socket_path)
            .await
            .context("Failed to connect to kprotect daemon for streaming")?;
        
        // The daemon automatically streams events to all connected clients
        // No command needed - just keep the connection open
        Ok(stream)
    }
    
    /// Get daemon status (health, uptime, eBPF status)
    pub async fn get_daemon_status(&self) -> Result<DaemonStatus> {
        let response = self.send_command("STATUS").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse daemon status")
    }
    
    /// Get encryption information
    pub async fn get_encryption_info(&self) -> Result<EncryptionInfo> {
        let response = self.send_command("ENCRYPTION_INFO").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse encryption info")
    }
    
    /// Get system information (policy stats, eBPF maps)
    pub async fn get_system_info(&self) -> Result<SystemInfo> {
        let response = self.send_command("SYSTEM_INFO").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse system info")
    }

    /// Get resource usage statistics (current/max for maps)
    pub async fn get_stats(&self) -> Result<kprotect_common::SystemStats> {
        let response = self.send_command("GET_STATS").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse resource statistics")
    }
}

impl Default for KprotectClient {
    fn default() -> Self {
        Self::new()
    }
}

/// Daemon capabilities
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Capabilities {
    pub version: String,
    pub protocol_version: String,
    pub features: Vec<String>,
    pub permissions: Permissions,
    pub resources: Vec<String>,
}

/// User permissions
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permissions {
    pub current_user: String,
    pub can_authorize: bool,
    pub can_revoke: bool,
    pub can_modify_zones: bool,
}

/// Resource schema
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Schema {
    pub resource: String,
    pub description: String,
    pub fields: Vec<SchemaField>,
    #[serde(default)]
    pub actions: Vec<SchemaAction>,
}

/// Schema field definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaField {
    pub name: String,
    #[serde(rename = "type")]
    pub field_type: String,
    #[serde(default)]
    pub required: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pattern: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_length: Option<usize>,
    pub description: String,
    pub display_name: String,
    #[serde(default)]
    pub readonly: bool,
}

/// Schema action definition
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaAction {
    pub name: String,
    pub command: String,
    pub requires_root: bool,
    pub parameters: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_ping() {
        let client = KprotectClient::new();
        let result = client.ping().await;
        // Test will fail if daemon not running - that's OK
        if let Ok(response) = result {
            assert!(response.contains("PONG"));
        }
    }
}

// ============================================================================
// Policy Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZonesConfig {
    pub red_zones: Vec<String>,
    #[serde(default)]
    pub green_zones: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EnrichmentConfig {
    pub enrichment_patterns: Vec<String>,
}

// ============================================================================
// System Monitoring Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub uptime_seconds: u64,
    pub ebpf_loaded: bool,
    pub active_connections: u32,
    pub socket_path: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptionInfo {
    pub enabled: bool,
    pub algorithm: String,
    pub key_fingerprint: String,
    pub policy_files: Vec<PolicyFileInfo>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyFileInfo {
    pub path: String,
    pub last_modified: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemInfo {
    pub authorized_patterns: usize,
    pub red_zones: usize,
    pub enrichment_patterns: usize,
    pub events_verified: u64,
    pub events_blocked: u64,
    pub lineage_cache_size: usize,
    #[serde(default)]
    pub event_log_size_bytes: u64,
    #[serde(default)]
    pub audit_log_size_bytes: u64,
    pub ebpf_maps: std::collections::HashMap<String, MapStats>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MapStats {
    pub size: u32,
    pub capacity: u32,
}

// ============================================================================
// Log Management Types
// ============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LogConfig {
    pub event_log_retention_days: u32,
    pub audit_log_retention_days: u32,
    pub event_log_enabled: bool,
    pub audit_log_enabled: bool,
}

// LogEntry is now imported from kprotect_common

// ============================================================================
// Policy Management Methods
// ============================================================================

impl KprotectClient {
    /// Add a zone pattern
    pub async fn add_zone(&self, zone_type: &str, pattern: &str) -> Result<()> {
        let cmd = format!("ZONE_ADD;{};{}", zone_type, pattern);
        let response = self.send_command(&cmd).await?;
        
        if !response.starts_with("OK") {
            anyhow::bail!("Failed to add zone: {}", response);
        }
        
        Ok(())
    }
    
    /// Remove a zone pattern
    pub async fn remove_zone(&self, zone_type: &str, pattern: &str) -> Result<()> {
        let cmd = format!("ZONE_REMOVE;{};{}", zone_type, pattern);
        let response = self.send_command(&cmd).await?;
        
        if !response.starts_with("OK") {
            anyhow::bail!("Failed to remove zone: {}", response);
        }
        
        Ok(())
    }
    
    /// List all zones
    pub async fn list_zones(&self) -> Result<ZonesConfig> {
        let response = self.send_command("ZONE_LIST").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse zones")
    }
    
    /// Add an enrichment pattern
    pub async fn add_enrichment_pattern(&self, pattern: &str) -> Result<()> {
        let cmd = format!("PATTERN_ADD;{}", pattern);
        let response = self.send_command(&cmd).await?;
        
        if !response.starts_with("OK") {
            anyhow::bail!("Failed to add pattern: {}", response);
        }
        
        Ok(())
    }
    
    /// Remove an enrichment pattern
    pub async fn remove_enrichment_pattern(&self, pattern: &str) -> Result<()> {
        let cmd = format!("PATTERN_REMOVE;{}", pattern);
        let response = self.send_command(&cmd).await?;
        
        if !response.starts_with("OK") {
            anyhow::bail!("Failed to remove pattern: {}", response);
        }
        
        Ok(())
    }
    
    /// List all enrichment patterns
    pub async fn list_enrichment_patterns(&self) -> Result<EnrichmentConfig> {
        let response = self.send_command("PATTERN_LIST").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse patterns")
    }

    // ============================================================================
    // Log Management Methods
    // ============================================================================

    /// Get current log configuration
    pub async fn get_log_config(&self) -> Result<LogConfig> {
        let response = self.send_command("GET_LOG_CONFIG").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse log config")
    }

    /// Set log retention policies (Root only)
    pub async fn set_log_retention(&self, event_days: u32, audit_days: u32) -> Result<()> {
        let cmd = format!("SET_LOG_RETENTION;{};{}", event_days, audit_days);
        let response = self.send_command(&cmd).await?;
        
        if response.starts_with("OK:") {
            Ok(())
        } else {
            anyhow::bail!("Failed to set log retention: {}", response)
        }
    }

    /// Get security events with pagination (Root only)
    pub async fn get_events(&self, count: usize, offset: usize) -> Result<Vec<LogEntry>> {
        let cmd = format!("GET_EVENTS;{};{}", count, offset);
        let response = self.send_command(&cmd).await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse security events")
    }

    /// Get audit entries with pagination (Root only)
    pub async fn get_audit(&self, count: usize, offset: usize) -> Result<Vec<LogEntry>> {
        let cmd = format!("GET_AUDIT;{};{}", count, offset);
        let response = self.send_command(&cmd).await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse audit logs")
    }

    // ============================================================================
    // Notification Management
    // ============================================================================

    /// Get all notification rules
    pub async fn get_notification_rules(&self) -> Result<Vec<kprotect_common::NotificationRule>> {
        let response = self.send_command("LIST_NOTIFY_RULES").await?;
        let json = self.parse_response(&response)?;
        serde_json::from_str(&json).context("Failed to parse notification rules")
    }

    /// Add a new notification rule (Root only)
    pub async fn add_notification_rule(
        &self,
        name: &str,
        event_types: &[kprotect_common::EventTypeFilter],
        path_pattern: Option<&str>,
        action_type: kprotect_common::ActionType,
        destination: &str,
        timeout: u32,
    ) -> Result<()> {
        let event_types_str = event_types
            .iter()
            .map(|et| match et {
                kprotect_common::EventTypeFilter::Verified => "Verified",
                kprotect_common::EventTypeFilter::Blocked => "Blocked",
            })
            .collect::<Vec<_>>()
            .join(",");

        let action_type_str = match action_type {
            kprotect_common::ActionType::Script => "Script",
            kprotect_common::ActionType::Webhook => "Webhook",
        };

        let path_str = path_pattern.unwrap_or("");

        let cmd = format!(
            "ADD_NOTIFY_RULE;{};{};{};{};{};{}",
            name, event_types_str, path_str, action_type_str, destination, timeout
        );

        let response = self.send_command(&cmd).await?;
        if response.starts_with("OK") {
            Ok(())
        } else {
            anyhow::bail!("Failed to add notification rule: {}", response)
        }
    }

    /// Remove a notification rule (Root only)
    pub async fn remove_notification_rule(&self, id: u32) -> Result<()> {
        let cmd = format!("REMOVE_NOTIFY_RULE;{}", id);
        let response = self.send_command(&cmd).await?;
        if response.starts_with("OK") {
            Ok(())
        } else {
            anyhow::bail!("Failed to remove notification rule: {}", response)
        }
    }

    /// Toggle a notification rule on/off (Root only)
    pub async fn toggle_notification_rule(&self, id: u32, enabled: bool) -> Result<()> {
        let cmd = format!("TOGGLE_NOTIFY_RULE;{};{}", id, enabled);
        let response = self.send_command(&cmd).await?;
        if response.starts_with("OK") {
            Ok(())
        } else {
            anyhow::bail!("Failed to toggle notification rule: {}", response)
        }
    }

    /// Get notification statistics (computed client-side)
    pub async fn get_notification_stats(&self) -> Result<Vec<kprotect_common::NotificationStats>> {
        let rules = self.get_notification_rules().await?;
        
        let stats = rules
            .iter()
            .map(|rule| {
                let total_triggers = rule.trigger_count;
                let success_rate = if total_triggers > 0 {
                    (rule.success_count as f64 / total_triggers as f64) * 100.0
                } else {
                    0.0
                };
                
                let avg_execution_ms = if total_triggers > 0 {
                    rule.total_execution_ms as f64 / total_triggers as f64
                } else {
                    0.0
                };
                
                kprotect_common::NotificationStats {
                    rule_id: rule.id,
                    rule_name: rule.name.clone(),
                    total_triggers,
                    success_count: rule.success_count,
                    failure_count: rule.failure_count,
                    timeout_count: rule.timeout_count,
                    success_rate,
                    avg_execution_ms,
                    last_triggered: rule.last_triggered,
                }
            })
            .collect();
            
        Ok(stats)
    }
}

