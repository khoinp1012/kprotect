use anyhow::{Context, Result, anyhow};
use kprotect_common::{NotificationRule, NotificationLogEntry, ActionType, EventTypeFilter, path_matcher::PathMatcher};
use log::{info, error, warn};
use std::sync::Arc;
use tokio::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH, Instant};
use std::path::Path;
use std::fs::{File, OpenOptions};
use std::io::Write;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

const NOTIFICATION_LOG_PATH: &str = "/var/log/kprotect/notifications.jsonl.enc";
const MAX_LOG_SIZE_BYTES: u64 = 10 * 1024 * 1024; // 10 MB
const MAX_LOG_FILES: usize = 5;

pub struct NotificationLogger {
    log_file: Arc<Mutex<File>>,
    log_path: String,
    key: [u8; 32],
}

impl NotificationLogger {
    pub fn new(log_path: Option<String>, key: [u8; 32]) -> Result<Self> {
        let log_path = log_path.unwrap_or_else(|| NOTIFICATION_LOG_PATH.to_string());
        
        // Create log directory if it doesn't exist
        if let Some(parent) = Path::new(&log_path).parent() {
            std::fs::create_dir_all(parent)
                .context("Failed to create notification log directory")?;
        }
        
        // Open or create log file in append mode
        let log_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&log_path)
            .context("Failed to open notification log file")?;
        
        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&log_path, permissions)?;
        }
        
        Ok(Self {
            log_file: Arc::new(Mutex::new(log_file)),
            log_path,
            key,
        })
    }
    
    pub async fn log(&self, entry: &NotificationLogEntry) -> Result<()> {
        // Check if rotation is needed
        self.rotate_if_needed().await?;
        
        // Get current timestamp
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs();

        // Generate unique nonce (8 bytes timestamp + 4 bytes random)
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[0..8].copy_from_slice(&timestamp.to_le_bytes());
        rand::thread_rng().fill_bytes(&mut nonce_bytes[8..]);

        // Serialize entry to JSON
        let json = serde_json::to_string(entry)
            .context("Failed to serialize notification log entry")?;

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| anyhow!("Invalid encryption key"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Write: timestamp:nonce:ciphertext
        let mut file = self.log_file.lock().await;
        writeln!(
            file,
            "{}:{}:{}",
            timestamp,
            hex::encode(nonce_bytes),
            hex::encode(ciphertext)
        )?;

        file.flush()?;
        Ok(())
    }
    
    async fn rotate_if_needed(&self) -> Result<()> {
        let metadata = match std::fs::metadata(&self.log_path) {
            Ok(m) => m,
            Err(_) => return Ok(()), // File doesn't exist yet
        };
        
        if metadata.len() < MAX_LOG_SIZE_BYTES {
            return Ok(()); // No rotation needed
        }
        
        // Rotate logs: .enc.4 -> delete, .enc.3 -> .enc.4, etc.
        for i in (1..MAX_LOG_FILES).rev() {
            let old_path = format!("{}.{}", self.log_path, i);
            let new_path = format!("{}.{}", self.log_path, i + 1);
            
            if Path::new(&old_path).exists() {
                if i == MAX_LOG_FILES - 1 {
                    let _ = std::fs::remove_file(&old_path); // Delete oldest
                } else {
                    let _ = std::fs::rename(&old_path, &new_path);
                }
            }
        }
        
        // Move current log to .enc.1
        let backup_path = format!("{}.1", self.log_path);
        
        // Need to close current file, rotate, and reopen
        drop(self.log_file.lock().await);
        std::fs::rename(&self.log_path, backup_path)?;
        
        // Reopen the file
        let new_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&self.log_path)?;
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(&self.log_path, permissions)?;
        }
        
        *self.log_file.lock().await = new_file;
        
        info!("Rotated notification log");
        Ok(())
    }
}

pub struct NotificationManager {
    rules: Arc<Mutex<Vec<NotificationRule>>>,
    logger: Arc<NotificationLogger>,
}

impl NotificationManager {
    pub fn new(rules: Vec<NotificationRule>, encryption_key: [u8; 32]) -> Self {
        let logger = Arc::new(
            NotificationLogger::new(None, encryption_key)
                .unwrap_or_else(|e| {
                    warn!("Failed to create notification logger: {}, logging disabled", e);
                    // Fallback to /dev/null with dummy key (won't be used)
                    NotificationLogger {
                        log_file: Arc::new(Mutex::new(
                            OpenOptions::new().write(true).open("/dev/null").unwrap()
                        )),
                        log_path: "/dev/null".to_string(),
                        key: [0u8; 32],
                    }
                })
        );
        
        Self {
            rules: Arc::new(Mutex::new(rules)),
            logger,
        }
    }

    pub async fn match_and_dispatch(&self, event_type: EventTypeFilter, path: &str, event_data: serde_json::Value) {
        let rules = self.rules.lock().await;
        for rule in rules.iter() {
            if !rule.enabled {
                continue;
            }

            // Check event type
            if !rule.event_types.contains(&event_type) {
                continue;
            }

            // Check path pattern
            if let Some(pattern) = &rule.path_pattern {
                let mut matcher = PathMatcher::new();
                if let Err(e) = matcher.add_rule(pattern) {
                    error!("Invalid path pattern in notification rule {} ({}): {}", rule.id, rule.name, e);
                    continue;
                }
                if !matcher.matches(path) {
                    continue;
                }
            }

            // Match found! Dispatch action in background
            let rule_clone = rule.clone();
            let event_data_clone = event_data.clone();
            let rules_handle = self.rules.clone();
            let logger = self.logger.clone();
            let rule_id = rule.id;
            let path_str = path.to_string();
            let event_type_str = format!("{:?}", event_type);

            tokio::spawn(async move {
                let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap_or_default().as_secs();
                let start = Instant::now();
                
                let result = match rule_clone.action_type {
                    ActionType::Script => {
                        dispatch_script(&rule_clone.destination, event_data_clone.clone(), rule_clone.timeout).await
                    }
                    ActionType::Webhook => {
                        dispatch_webhook(&rule_clone.destination, event_data_clone.clone(), rule_clone.timeout).await
                    }
                };
                
                let execution_ms = start.elapsed().as_millis() as u64;
                let event_id = event_data_clone.get("id").and_then(|v| v.as_u64()).unwrap_or(0);
                
                // Determine status and update stats
                let (status, error_msg) = match &result {
                    Ok(_) => ("Success", None),
                    Err(e) => {
                        let err_str = e.to_string();
                        if err_str.contains("timed out") {
                            ("Timeout", Some(err_str))
                        } else {
                            ("Failed", Some(err_str))
                        }
                    }
                };
                
                // Log the dispatch (encrypted)
                let log_entry = NotificationLogEntry {
                    timestamp: now,
                    rule_id,
                    rule_name: rule_clone.name.clone(),
                    event_type: event_type_str,
                    matched_path: path_str.clone(),
                    action: format!("{:?}", rule_clone.action_type),
                    destination: rule_clone.destination.clone(),
                    status: status.to_string(),
                    execution_ms,
                    error: error_msg.clone(),
                    event_id,
                };
                
                if let Err(e) = logger.log(&log_entry).await {
                    warn!("Failed to write notification log: {}", e);
                }
                
                // Update stats
                let mut rules_lock = rules_handle.lock().await;
                if let Some(r) = rules_lock.iter_mut().find(|r| r.id == rule_id) {
                    r.last_triggered = Some(now);
                    r.trigger_count += 1;
                    r.total_execution_ms += execution_ms;
                    
                    match status {
                        "Success" => {
                            r.success_count += 1;
                            info!("✅ Notification triggered for rule {} ({}) → {} in {}ms", 
                                  rule_id, r.name, path_str, execution_ms);
                        }
                        "Timeout" => {
                            r.timeout_count += 1;
                            warn!("⏱️  Notification timeout for rule {} ({}) after {}ms: {}", 
                                  rule_id, r.name, execution_ms, error_msg.unwrap_or_default());
                        }
                        "Failed" => {
                            r.failure_count += 1;
                            error!("❌ Notification failed for rule {} ({}): {}", 
                                   rule_id, r.name, error_msg.unwrap_or_default());
                        }
                        _ => {}
                    }
                }
            });
        }
    }

    pub async fn add_rule(&self, mut rule: NotificationRule) -> Result<u32> {
        let mut rules = self.rules.lock().await;
        
        // Check for duplicate name
        if rules.iter().any(|r| r.name == rule.name) {
            anyhow::bail!("Notification rule with name '{}' already exists. Please use a unique name.", rule.name);
        }
        
        let id = rules.iter().map(|r| r.id).max().unwrap_or(0) + 1;
        rule.id = id;
        rule.created_at = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();
        
        // Initialize stats
        rule.success_count = 0;
        rule.failure_count = 0;
        rule.timeout_count = 0;
        rule.total_execution_ms = 0;
        
        rules.push(rule);
        Ok(id)
    }

    pub async fn remove_rule(&self, id: u32) -> Result<()> {
        let mut rules = self.rules.lock().await;
        rules.retain(|r| r.id != id);
        Ok(())
    }

    pub async fn toggle_rule(&self, id: u32, enabled: bool) -> Result<()> {
        let mut rules = self.rules.lock().await;
        if let Some(rule) = rules.iter_mut().find(|r| r.id == id) {
            rule.enabled = enabled;
            Ok(())
        } else {
            anyhow::bail!("Rule not found")
        }
    }

    pub async fn get_rules(&self) -> Vec<NotificationRule> {
        self.rules.lock().await.clone()
    }
}

async fn dispatch_script(path: &str, event_data: serde_json::Value, timeout_secs: u32) -> Result<()> {
    let mut cmd = tokio::process::Command::new(path);
    
    // Pass event data via environment variables
    if let Some(obj) = event_data.as_object() {
        for (key, value) in obj {
            let env_key = format!("KPROTECT_{}", key.to_uppercase());
            let val_str = match value {
                serde_json::Value::String(s) => s.clone(),
                _ => value.to_string(),
            };
            cmd.env(env_key, val_str);
        }
    }

    // Also pass raw JSON
    cmd.env("KPROTECT_EVENT_JSON", event_data.to_string());

    let mut child = cmd.spawn().context("Failed to spawn notification script")?;

    tokio::select! {
        status = child.wait() => {
            let status = status?;
            if !status.success() {
                anyhow::bail!("Script exited with non-zero status: {}", status);
            }
            Ok(())
        }
        _ = tokio::time::sleep(tokio::time::Duration::from_secs(timeout_secs as u64)) => {
            let _ = child.kill().await;
            anyhow::bail!("Script timed out after {}s", timeout_secs);
        }
    }
}

async fn dispatch_webhook(url: &str, event_data: serde_json::Value, timeout_secs: u32) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(tokio::time::Duration::from_secs(timeout_secs as u64))
        .build()?;

    let response = client.post(url)
        .json(&event_data)
        .send()
        .await?;

    if !response.status().is_success() {
        anyhow::bail!("Webhook failed with status: {}", response.status());
    }

    Ok(())
}
