use anyhow::{Result, Context};
use std::fs;
use std::os::unix::fs::PermissionsExt;
use std::sync::Arc;
use tokio::sync::{broadcast, Mutex};
use tokio::net::UnixListener;
use std::collections::HashMap;
use log::{info, warn, error};
use aya::maps::HashMap as BpfHashMap;
use aya::maps::lpm_trie::LpmTrie;
use aya::maps::MapData;

use crate::state::{self, AppState};
use kprotect_common::AuthorizedPattern;
use crate::core::domain::{LineageNode, ChainTrieNode, PatternType, PathKey};
use crate::core::auth::{rebuild_auth_caches, parse_pattern, insert_prefix, insert_suffix};
use crate::crypto;
use crate::migration::{self, ZonesFile};
use crate::config::{self};
use crate::logger;
use crate::notifications;
use crate::server::api::handle_client;

const PID_FILE: &str = "/run/kprotect/kprotect.pid";
const SOCKET_PATH: &str = "/run/kprotect/kprotect.sock";
const AUTHORIZED_PATTERNS_PATH: &str = "/var/lib/kprotect/configs/authorized_patterns.enc";
const NOTIFICATION_RULES_PATH: &str = "/var/lib/kprotect/configs/notifications.enc";
const MAX_RED_ZONE_PATTERNS: usize = 192;

pub async fn start_daemon() -> Result<()> {
    info!("🛡️ Starting kprotect Daemon");
    
    // Check for existing daemon via PID file
    if let Ok(pid_str) = fs::read_to_string(PID_FILE) {
        if let Ok(pid) = pid_str.trim().parse::<i32>() {
            // Check if process is still running
            if std::path::Path::new(&format!("/proc/{}", pid)).exists() {
                anyhow::bail!(
                    "❌ Another kprotect daemon is already running (PID: {})\n\
                     To stop it: sudo kill {}\n\
                     Or if stale: sudo rm {}",
                    pid, pid, PID_FILE
                );
            } else {
                // Stale PID file, remove it
                info!("🧹 Removing stale PID file (process {} no longer exists)", pid);
                let _ = fs::remove_file(PID_FILE);
            }
        }
    }
    
    // Write our PID file
    let my_pid = std::process::id();
    fs::write(PID_FILE, my_pid.to_string())
        .context("Failed to write PID file - are you running as root?")?;
    info!("📝 PID file created: {} (PID: {})", PID_FILE, my_pid);
    
    // Step 1: Initialize salt (MUST be first, before any eBPF loading)
    info!("🔐 Initializing cryptography...");
    crypto::ensure_salt()
        .context("Failed to initialize salt file")?;
    
    let key = crypto::derive_key()
        .context("Failed to derive encryption key")?;
    
    info!("✅ Encryption key derived successfully");
    
    let (event_tx, _) = broadcast::channel(1024); // Increased buffer for boot-time bursts
    
    // ═══════════════════════════════════════════════════════════════════════════════
    // CRITICAL: Load eBPF FIRST - Before ANY config loading!
    // This ensures we monitor ALL system activity from the very beginning
    // ═══════════════════════════════════════════════════════════════════════════════
    info!("🚀 Loading eBPF hooks (PRIORITY: Capture all early boot activity)");
    let mut bpf = crate::ebpf::manager::load_ebpf()
        .context("Failed to load eBPF - are you running as root with CAP_BPF?")?;
    info!("⚡ eBPF loaded and attached - lineage tracking is LIVE");

    // ═══════════════════════════════════════════════════════════════════════════════
    // CRITICAL: Extract maps and start monitoring IMMEDIATELY
    // Must happen BEFORE config loading to prevent losing BIRTH events in perf buffer
    // ═══════════════════════════════════════════════════════════════════════════════
    info!("📦 Extracting eBPF maps for immediate monitoring...");
    let event_tx_init = event_tx.clone();
    
    let auth_map: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
        bpf.take_map("AUTHORIZED_SIGNATURES").context("Map not found")?
    )?;
    let shared_auth_map = Arc::new(Mutex::new(auth_map));

    let red_exact_map: BpfHashMap<_, u64, u8> = BpfHashMap::try_from(
        bpf.take_map("RED_EXACT_MAP").context("RED_EXACT_MAP not found")?
    )?;
    let red_prefix_map: LpmTrie<_, PathKey, u8> = LpmTrie::try_from(
        bpf.take_map("RED_PREFIX_MAP").context("RED_PREFIX_MAP not found")?
    )?;
    let red_suffix_map: LpmTrie<_, PathKey, u8> = LpmTrie::try_from(
        bpf.take_map("RED_SUFFIX_MAP").context("RED_SUFFIX_MAP not found")?
    )?;
    let enrichment_prefix_map: LpmTrie<_, PathKey, u8> = LpmTrie::try_from(
        bpf.take_map("ENRICHMENT_PREFIX_MAP").context("ENRICHMENT_PREFIX_MAP not found")?
    )?;
    let event_map = bpf.take_map("EVENTS").context("Map not found")?;
    let sig_map: BpfHashMap<_, u32, u64> = BpfHashMap::try_from(
        bpf.take_map("PROCESS_SIGNATURES").context("Map not found")?
    )?;

    let shared_red_exact = Arc::new(Mutex::new(red_exact_map));
    let shared_red_prefix = Arc::new(Mutex::new(red_prefix_map));
    let shared_red_suffix = Arc::new(Mutex::new(red_suffix_map));
    let shared_enrichment_prefix = Arc::new(Mutex::new(enrichment_prefix_map));
    let shared_sig_map = Arc::new(Mutex::new(sig_map));

    // Create minimal temporary state for immediate monitoring
    let temp_state_obj = AppState {
        lineage_cache: HashMap::new(),
        event_tx: event_tx_init.clone(),
        authorized_patterns: Vec::new(),  // Will be loaded later
        auth_exact_cache: HashMap::new(),
        auth_suffix_cache: ChainTrieNode::new(),
        event_sequence: 0,
        events_verified: 0,
        events_blocked: 0,
        encryption_key: key.clone(),
        start_time: std::time::Instant::now(),
        red_exact: shared_red_exact.clone(),
        red_prefix: shared_red_prefix.clone(),
        red_suffix: shared_red_suffix.clone(),
        red_enrichment_prefix: shared_enrichment_prefix.clone(),
        auth_map: shared_auth_map.clone(),
        logger: Arc::new(logger::EncryptedLogger::new(key.clone())?),  // Temp logger
        config: Arc::new(Mutex::new(config::DaemonConfig::default())),
        notification_manager: Arc::new(notifications::NotificationManager::new(Vec::new(), key.clone())),
    };
    
    let state = Arc::new(Mutex::new(temp_state_obj));
    
    info!("🔍 Starting lineage event monitor NOW (ZERO latency - capturing all early boot processes)");
    let state_clone = state.clone();
    let auth_map_clone = shared_auth_map.clone();
    let sig_map_clone = shared_sig_map.clone();

    tokio::spawn(async move {
        if let Err(e) = crate::ebpf::events::monitor_ebpf_events(event_map, state_clone, auth_map_clone, sig_map_clone).await {
            error!("Event monitor error: {}", e);
        }
    });
    info!("✅ Lineage monitor spawned - ALL processes from this point will have complete chains!");
    

    // ═══════════════════════════════════════════════════════════════════════════════
    // NOW load configs and update state (monitoring is already running)
    // ═══════════════════════════════════════════════════════════════════════════════
    info!("� Loading configuration files...");
    
    // Load daemon config (needed for logger initialization)
    let daemon_config = config::load_config(&key)
        .unwrap_or_else(|_| {
            info!("Creating default daemon config");
            config::DaemonConfig::default()
        });
    config::save_config(&daemon_config, &key)?;
    info!("✅ Daemon config loaded (event retention: {} days, audit retention: {} days)",
          daemon_config.event_log_retention_days, daemon_config.audit_log_retention_days);

    // Create encrypted logger
    let logger = Arc::new(logger::EncryptedLogger::new(key.clone())?);  
    info!("✅ Encrypted logger initialized");

    // Initialize configs with defaults if they don't exist (with audit logging)
    migration::ensure_encrypted_configs(&key, &logger)
        .context("Failed to initialize configuration files")?;
    
    // NOW load encrypted configs (they exist for sure after ensure_encrypted_configs)
    let mut zones: migration::ZonesFile = crypto::load_encrypted(
        "/var/lib/kprotect/configs/zones.enc", &key)
        .context("Failed to load encrypted zones")?;
    
    // SAFETY: If zones are empty/corrupted, recreate with defaults
    if zones.red_zones.is_empty() && zones.green_zones.is_empty() {
        warn!("⚠️ Zones file is empty, recreating with defaults");
        zones = migration::ZonesFile { 
            green_zones: vec![],
            red_zones: vec![
                // === SSH Keys (Critical) ===
                "*/id_rsa".to_string(),
                "*/id_ed25519".to_string(),
                "*/id_ecdsa".to_string(),
                "*/id_dsa".to_string(),
                
                // === Cloud Credentials (Critical) ===
                "*/credentials".to_string(),  // AWS/Cargo credentials
                "*/.config/gcloud/application_default_credentials.json".to_string(),  // GCP
                "*/azure.json".to_string(),
                "*/.kube/config".to_string(),  // Kubernetes config
                
                // === Application Secrets (High Priority) ===
                "*/.env".to_string(),
                "*/.env.local".to_string(),
                "*/.env.production".to_string(),
                "*/secrets.yml".to_string(),
                "*/secrets.yaml".to_string(),
                
                // === Password Managers (Critical) ===
                "*.kdbx".to_string(),           // KeePass
                "*/.password-store/".to_string(), // pass utility
                
                // === Private Keys & Certificates ===
                "*.p12".to_string(),            // PKCS#12 bundles
                "/etc/ssl/private/*".to_string(),
                "*/privkey.pem".to_string(),    // Let's Encrypt private keys
                
                // === Database Credentials ===
                "*/my.cnf".to_string(),         // MySQL config
                "*/.my.cnf".to_string(),
                "*/.pgpass".to_string(),        // PostgreSQL password file
                "*/redis.conf".to_string(),
                
                // === Browser Saved Passwords ===
                "*/logins.json".to_string(),    // Firefox
                "*/Login Data".to_string(),     // Chrome/Chromium
                
                // === Browser Cookies (Session Hijacking) ===
                "*/Cookies".to_string(),        // Chrome, Edge, Brave, Vivaldi, Opera
                "*/cookies.sqlite".to_string(), // Firefox
                
                // === Git & Version Control ===
                "*/.git-credentials".to_string(),
                "*/.netrc".to_string(),
                "*/.config/gh/hosts.yml".to_string(), // GitHub CLI
                
                // === Package Manager Credentials ===
                "*/.npmrc".to_string(),         // npm
                "*/.pypirc".to_string(),        // PyPI
                "*/auth.json".to_string(),      // Composer
                
                // === Container/Docker ===
                "*/.docker/config.json".to_string(),
                
                // === Token Files ===
                "*/.boto".to_string(),          // AWS boto config
                "*/.vault-token".to_string(),   // HashiCorp Vault
            ]
        };
        crypto::save_encrypted(&zones, "/var/lib/kprotect/configs/zones.enc", &key)?;
        logger.log_audit("FIX_EMPTY_CONFIG", "system", serde_json::json!({
            "config_file": "zones.enc",
            "red_zones_count": zones.red_zones.len(),
            "reason": "empty_file_detected"
        }), true)?;
    }
    
    let mut enrichment_patterns: Vec<String> = crypto::load_encrypted(
        "/var/lib/kprotect/configs/enrichment.enc", &key)
        .unwrap_or_else(|_| {
            info!("No enrichment patterns file found, creating defaults");
            vec![]
        });
    
    // SAFETY: If enrichment patterns are empty, recreate with defaults
    if enrichment_patterns.is_empty() {
        warn!("⚠️ Enrichment patterns file is empty, recreating with defaults");
        enrichment_patterns = vec![
            "/usr/bin/python*".to_string(),
            "/bin/python*".to_string(),
            "/usr/bin/node*".to_string(),
            "/bin/node*".to_string(),
            "*/bin/bash".to_string(),
            "*/bin/sh".to_string(),
            "*/bin/zsh".to_string(),
            "*/bin/ruby".to_string(),
            "*/bin/perl".to_string(),
            "*/bin/php".to_string(),
        ];
        crypto::save_encrypted(&enrichment_patterns, "/var/lib/kprotect/configs/enrichment.enc", &key).ok();
        logger.log_audit("FIX_EMPTY_CONFIG", "system", serde_json::json!({
            "config_file": "enrichment.enc",
            "patterns_count": enrichment_patterns.len(),
            "reason": "empty_file_detected"
        }), true).ok();
    }
    
    info!("✅ Loaded encrypted configs");
    info!("  📋 Red zones: {}, Green zones: {}", zones.red_zones.len(), zones.green_zones.len());
    info!("  🔧 Enrichment patterns: {}", enrichment_patterns.len());

    // Load persistent authorized patterns (NEW pattern-based authorization)
    let authorized_patterns: Vec<AuthorizedPattern> = crypto::load_encrypted(AUTHORIZED_PATTERNS_PATH, &key)
        .unwrap_or_else(|_| {
            info!("No authorized patterns file found, starting fresh.");
            Vec::new()
        });
    info!("  📜 Authorized patterns: {}", authorized_patterns.len());
    
    // Load persistent notification rules
    let notification_rules: Vec<kprotect_common::NotificationRule> = crypto::load_encrypted(NOTIFICATION_RULES_PATH, &key)
        .unwrap_or_else(|_| {
            info!("No notification rules file found, starting fresh.");
            Vec::new()
        });
    info!("  🔔 Notification rules: {}", notification_rules.len());

    // Initialize Notification Manager
    let notification_manager = Arc::new(notifications::NotificationManager::new(notification_rules, key.clone()));

    // Log daemon start
    logger.log_audit("DAEMON_START", "system", serde_json::json!({
        "version": env!("CARGO_PKG_VERSION"),
        "event_retention_days": daemon_config.event_log_retention_days,
        "audit_retention_days": daemon_config.audit_log_retention_days,
    }), true)?;

    // Initialize event sequence from the highest ID in the logs.
    // We no longer rely on a separate state file to prevent disk I/O bottlenecks.
    let initial_id = logger.get_max_event_id();
    info!("✅ Event sequence initialized at #{}", initial_id);

    // Build auth caches before updating state
    let mut auth_exact_cache = HashMap::new();
    let mut auth_suffix_cache = ChainTrieNode::new();
    rebuild_auth_caches(&authorized_patterns, &mut auth_exact_cache, &mut auth_suffix_cache);
    
    // Update state with loaded configs
    {
        let mut state_lock = state.lock().await;
        state_lock.authorized_patterns = authorized_patterns;
        state_lock.event_sequence = initial_id;
        state_lock.logger = logger.clone();
        state_lock.config = Arc::new(Mutex::new(daemon_config.clone()));
        state_lock.notification_manager = notification_manager.clone();
        state_lock.auth_exact_cache = auth_exact_cache;
        state_lock.auth_suffix_cache = auth_suffix_cache;
    }

    // Clean up old socket
    let _ = fs::remove_file(SOCKET_PATH);

    // Load zones into eBPF maps
    load_zones(&state, Some(&zones)).await?;

    // Load enrichment patterns into eBPF map
    load_enrichment_patterns(&shared_enrichment_prefix, Some(&enrichment_patterns)).await?;

    // Spawn UDS Socket Server
    let listener = UnixListener::bind(SOCKET_PATH)?;
    // Allow unprivileged clients (CLI/GUI) to connect, we check UID in handle_client
    fs::set_permissions(SOCKET_PATH, fs::Permissions::from_mode(0o666))?;
    info!("📡 Listening on {}", SOCKET_PATH);
    
    // Spawn background log cleanup task
    let logger_clone = logger.clone();
    let config_clone = Arc::clone(&state.lock().await.config);
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600)); // Hourly
        loop {
            interval.tick().await;
            let cfg = config_clone.lock().await;
            if let Err(e) = logger_clone.cleanup_events(cfg.event_log_retention_days) {
                warn!("Failed to cleanup event logs: {}", e);
            }
            if let Err(e) = logger_clone.cleanup_audit(cfg.audit_log_retention_days) {
                warn!("Failed to cleanup audit logs: {}", e);
            }
            info!("🧹 Log cleanup completed");
        }
    });
    
    // Setup signal handler for graceful shutdown
    tokio::spawn(async move {
        tokio::signal::ctrl_c().await.ok();
        info!("🛑 Received shutdown signal, cleaning up...");
        let _ = fs::remove_file(PID_FILE);
        let _ = fs::remove_file(SOCKET_PATH);
        std::process::exit(0);
    });

    loop {
        match listener.accept().await {
            Ok((stream, _)) => {
                let state_clone = state.clone();
                // handle_client now accesses maps via state
                tokio::spawn(async move {
                    if let Err(e) = handle_client(stream, state_clone).await {
                        warn!("Client error: {}", e);
                    }
                });
            }
            Err(e) => error!("Socket accept error: {}", e),
        }
    }
}

/// Load zone rules from encrypted backup
async fn load_zones(state: &Arc<Mutex<AppState>>, backup_zones: Option<&migration::ZonesFile>) -> Result<()> {
    let zones: ZonesFile = if let Some(backup) = backup_zones {
        info!("🔒 Loading zones from encrypted storage");
        backup.clone()
    } else {
        anyhow::bail!("No zones configuration found");
    };

    // CRITICAL: Validate limits match eBPF constraints
    if zones.red_zones.len() > MAX_RED_ZONE_PATTERNS {
        anyhow::bail!(
            "Too many red zone patterns: {} (max {}). eBPF map limit exceeded!",
            zones.red_zones.len(),
            MAX_RED_ZONE_PATTERNS
        );
    }
    
    info!("Validating {} red zones against limit of {}...", zones.red_zones.len(), MAX_RED_ZONE_PATTERNS);

    // Process red zones
    let state_lock = state.lock().await;

    for pattern in &zones.red_zones {
        match parse_pattern(pattern)? {
            PatternType::Prefix(p) => {
                let mut map = state_lock.red_prefix.lock().await;
                insert_prefix(&mut *map, &p)?;
                info!("✓ Red Prefix: {}", pattern);
            }
            PatternType::Suffix(s) => {
                let mut map = state_lock.red_suffix.lock().await;
                insert_suffix(&mut *map, &s)?;
                info!("✓ Red Suffix: {}", pattern);
            }
            PatternType::Exact(e) => {
                let mut map = state_lock.red_exact.lock().await;
                let hash = fnv1a_hash(e.as_bytes());
                map.insert(hash, 1, 0)?;
                info!("✓ Red Exact: {} (0x{:x})", pattern, hash);
            }
        }
    }

    info!("✓ Loaded {} red zones", zones.red_zones.len());
    Ok(())
}

async fn load_enrichment_patterns(map_mutex: &Arc<Mutex<LpmTrie<MapData, PathKey, u8>>>, backup_patterns: Option<&Vec<String>>) -> Result<()> {
    let patterns = if let Some(backup) = backup_patterns {
        if !backup.is_empty() {
            info!("🔒 Loading enrichment patterns from encrypted storage");
            backup.clone()
        } else {
            vec![]
        }
    } else {
        vec![]
    };

    if patterns.is_empty() {
        info!("⚠️ No enrichment patterns loaded");
        return Ok(());
    }
        
    let mut map = map_mutex.lock().await;

    for pattern in patterns {
        match parse_pattern(&pattern) {
            Ok(PatternType::Prefix(p)) => {
                insert_prefix(&mut *map, &p)?;
                info!("✓ Enrichment Prefix: {}", pattern);
            }
            Ok(PatternType::Suffix(_)) => {
                // Reject suffix for enrichment - we only support prefix (ends with *) for command matching
                warn!("⚠️ Skipping invalid enrichment pattern '{}': Must be a prefix match (end with *)", pattern);
                continue;
            }
            Ok(PatternType::Exact(_)) => {
                warn!("⚠️ Skipping invalid enrichment pattern '{}': Must be a prefix match (end with *)", pattern);
                continue;
            }
            Err(e) => {
                error!("⚠️ Skipping invalid enrichment pattern '{}': {}", pattern, e);
                continue;
            }
        }
    }
    Ok(())
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
