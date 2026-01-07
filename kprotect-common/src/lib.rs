//! Shared types and constants for kprotect security framework
//!
//! This crate contains data structures shared between the eBPF kernel code
//! and the userspace daemon.

// kprotect-common: Shared types and utilities for kprotect
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

use serde::{Serialize, Deserialize};

pub mod path_matcher;

use serde_big_array::BigArray;

/// Core Event for the Ancestry Anchor system
#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct BridgeEvent {
    pub signature: u64,
    pub start_time: u64, // Unique process identity
    pub pid: u32,
    pub ppid: u32,
    pub event_type: u32,
    pub argc: u32, // Tracking number of arguments
    #[serde(with = "BigArray")]
    pub path: [u8; 256],
    #[serde(with = "BigArray")]
    pub arg: [u8; 64],
    pub comm: [u8; 16],
}

#[repr(C)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
pub struct FileAccessEvent {
    pub pid: u32,
    pub is_sensitive: u8,
    #[serde(with = "BigArray")]
    pub path: [u8; 4096],
    #[serde(with = "BigArray")]
    pub comm: [u8; 16],
}

/// Constants for event types
pub const EVENT_TYPE_VERIFIED: u32 = 1;
pub const EVENT_TYPE_BLOCK: u32 = 2;
pub const EVENT_TYPE_BIRTH: u32 = 3;
pub const EVENT_TYPE_EXIT: u32 = 4;

/// Pattern-based authorization types
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthorizedPattern {
    /// The lineage pattern as array of process paths
    pub pattern: Vec<String>,
    /// Human-readable description
    pub description: String,
    /// How to match this pattern against chains
    pub match_mode: MatchMode,
    /// Unix timestamp when authorized
    pub authorized_at: u64,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum MatchMode {
    /// Full chain must match exactly
    Exact,
    /// Chain must end with this pattern (suffix match)
    Suffix,
}

// ============================================================================
// Notification System Types
// ============================================================================

/// Notification rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationRule {
    pub id: u32,
    pub name: String,
    pub enabled: bool,
    
    // FILTER (Backend-side)
    pub event_types: Vec<EventTypeFilter>,
    pub path_pattern: Option<String>,  // Glob like "/etc/*" or "*.key"
    
    // ACTION
    pub action_type: ActionType,
    pub destination: String,           // Path to .sh or URL
    pub timeout: u32,                  // Max execution time (default: 30)
    
    // METADATA
    pub created_at: u64,
    pub last_triggered: Option<u64>,
    pub trigger_count: u64,
    
    // STATISTICS
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub total_execution_ms: u64,
}

/// Event type filter for notifications
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum EventTypeFilter {
    Verified,
    Blocked,
}

/// Action type for notifications
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ActionType {
    Script,
    Webhook,
}

/// Notification dispatch log entry
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationLogEntry {
    pub timestamp: u64,
    pub rule_id: u32,
    pub rule_name: String,
    pub event_type: String,
    pub matched_path: String,
    pub action: String,
    pub destination: String,
    pub status: String, // "Success", "Failed", "Timeout"
    pub execution_ms: u64,
    pub error: Option<String>,
    pub event_id: u64,
}

/// Notification statistics (aggregated)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NotificationStats {
    pub rule_id: u32,
    pub rule_name: String,
    pub total_triggers: u64,
    pub success_count: u64,
    pub failure_count: u64,
    pub timeout_count: u64,
    pub success_rate: f64,
    pub avg_execution_ms: f64,
    pub last_triggered: Option<u64>,
}

/// Resource usage statistics (current vs max capacity)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    pub current: usize,
    pub max: usize,
}

/// Zone-specific usage statistics for all three matching modes
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ZoneStats {
    pub prefix: ResourceUsage,
    pub suffix: ResourceUsage,
    pub exact: ResourceUsage,
}

/// Global system capacity statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStats {
    pub authorized_chains: ResourceUsage,
    pub enrichment: ResourceUsage,
    pub zones: ZoneStats,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum LogEntry {
    SecurityEvent {
        id: u64,
        timestamp: u64,
        status: String,
        pid: u32,
        comm: String,
        target: String,
        chain: Vec<String>,
        signature: String,
        authorized: bool,
        complete: bool,
    },
    AuditAction {
        timestamp: u64,
        action: String,
        username: String,
        details: serde_json::Value,
        success: bool,
    },
}
