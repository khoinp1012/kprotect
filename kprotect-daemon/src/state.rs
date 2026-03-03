use aya::maps::lpm_trie::LpmTrie;
use aya::maps::{HashMap as BpfHashMap, MapData};
use dashmap::DashMap;
use std::collections::HashMap;
use std::sync::atomic::AtomicU64;
use std::sync::Arc;
use std::sync::RwLock;
use tokio::sync::{broadcast, Mutex};

use crate::config;
use crate::core::domain::{ChainTrieNode, LineageNode, PathKey};
use crate::logger;
use crate::notifications;
use kprotect_common::AuthorizedPattern;

pub struct AppState {
    pub lineage_cache: Arc<DashMap<u32, LineageNode>>,
    pub event_tx: broadcast::Sender<String>,

    // Rules & Configuration (Wrapped in RwLock for high-concurrency reads)
    pub rules: RwLock<RulesState>,

    // Telemetry Statistics (Atomics for lock-free updates)
    pub event_sequence: AtomicU64,
    pub events_verified: AtomicU64,
    pub events_blocked: AtomicU64,
    pub sudo_events_verified: AtomicU64,
    pub sudo_events_blocked: AtomicU64,

    pub encryption_key: [u8; 32],
    pub start_time: std::time::Instant,
    pub notification_manager: Arc<notifications::NotificationManager>,

    // Map handles (Optional to allow testing without root/BPF)
    pub red_exact: Arc<Mutex<Option<BpfHashMap<MapData, u64, u8>>>>,
    pub red_prefix: Arc<Mutex<Option<LpmTrie<MapData, PathKey, u8>>>>,
    pub red_suffix: Arc<Mutex<Option<LpmTrie<MapData, PathKey, u8>>>>,
    pub red_enrichment_prefix: Arc<Mutex<Option<LpmTrie<MapData, PathKey, u8>>>>,
    pub auth_map: Arc<Mutex<Option<BpfHashMap<MapData, u64, u8>>>>,

    pub logger: Arc<logger::EncryptedLogger>,
    /// Cache of recent PAM-authorized elevations for deduplication: PID -> Timestamp
    pub last_pam_elevations: Arc<DashMap<u32, u64>>,
}

/// State that is updated via Management API and read by the Event Loop
pub struct RulesState {
    pub authorized_patterns: Vec<AuthorizedPattern>,
    pub sudo_rules: Vec<kprotect_common::SudoRule>,
    // Optimization Caches
    pub auth_exact_cache: HashMap<Vec<String>, AuthorizedPattern>,
    pub auth_suffix_cache: ChainTrieNode,
    pub config: config::DaemonConfig,
}

impl AppState {
    pub fn mock_test() -> Arc<Self> {
        let (event_tx, _) = broadcast::channel(100);
        let key = [0u8; 32];

        Arc::new(Self {
            lineage_cache: Arc::new(DashMap::new()),
            event_tx,
            rules: RwLock::new(RulesState {
                authorized_patterns: vec![],
                sudo_rules: vec![],
                auth_exact_cache: HashMap::new(),
                auth_suffix_cache: ChainTrieNode::new(),
                config: config::DaemonConfig::default(),
            }),
            event_sequence: AtomicU64::new(0),
            events_verified: AtomicU64::new(0),
            events_blocked: AtomicU64::new(0),
            sudo_events_verified: AtomicU64::new(0),
            sudo_events_blocked: AtomicU64::new(0),
            encryption_key: key,
            start_time: std::time::Instant::now(),
            notification_manager: Arc::new(notifications::NotificationManager::new(vec![], key)),
            red_exact: Arc::new(Mutex::new(None)),
            red_prefix: Arc::new(Mutex::new(None)),
            red_suffix: Arc::new(Mutex::new(None)),
            red_enrichment_prefix: Arc::new(Mutex::new(None)),
            auth_map: Arc::new(Mutex::new(None)),
            logger: Arc::new(
                logger::EncryptedLogger::new_custom(
                    key,
                    "/tmp/kprotect_test/events.enc".to_string(),
                    "/tmp/kprotect_test/audit.enc".to_string(),
                )
                .unwrap(),
            ),
            last_pam_elevations: Arc::new(DashMap::new()),
        })
    }
}
