use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use aya::maps::{HashMap as BpfHashMap, MapData};
use aya::maps::lpm_trie::LpmTrie;

use crate::core::domain::{LineageNode, ChainTrieNode, PathKey};
use kprotect_common::AuthorizedPattern;
use crate::logger;
use crate::config;
use crate::notifications;

pub struct AppState {
    pub lineage_cache: HashMap<u32, LineageNode>,
    pub event_tx: broadcast::Sender<String>,
    pub authorized_patterns: Vec<AuthorizedPattern>,
    // Optimization Caches
    pub auth_exact_cache: HashMap<Vec<String>, AuthorizedPattern>,
    pub auth_suffix_cache: ChainTrieNode,
    pub event_sequence: u64, // Monotonically increasing event ID
    pub events_verified: u64, // Total approved actions
    pub events_blocked: u64,  // Total blocked actions
    pub encryption_key: [u8; 32], // For saving encrypted configs
    pub start_time: std::time::Instant, // Daemon start time for uptime tracking
    pub notification_manager: Arc<notifications::NotificationManager>,
    // Red Zone eBPF Map Handles (for hot-loading)
    pub red_exact: Arc<Mutex<BpfHashMap<MapData, u64, u8>>>,
    pub red_prefix: Arc<Mutex<LpmTrie<MapData, PathKey, u8>>>,
    pub red_suffix: Arc<Mutex<LpmTrie<MapData, PathKey, u8>>>,
    pub red_enrichment_prefix: Arc<Mutex<LpmTrie<MapData, PathKey, u8>>>,
    // Auth Map Handle
    pub auth_map: Arc<Mutex<BpfHashMap<MapData, u64, u8>>>,
    // Logging & Configuration
    pub logger: Arc<logger::EncryptedLogger>,
    pub config: Arc<Mutex<config::DaemonConfig>>,
}
