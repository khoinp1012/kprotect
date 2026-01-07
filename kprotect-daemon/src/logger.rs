use anyhow::{anyhow, bail, Context, Result};
use kprotect_common::{BridgeEvent, LogEntry};
use serde::{Deserialize, Serialize};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write, Seek, SeekFrom};
use std::path::Path;
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Nonce};
use rand::RngCore;

const EVENTS_LOG_PATH: &str = "/var/log/kprotect/events.jsonl.enc";
const AUDIT_LOG_PATH: &str = "/var/log/kprotect/audit.jsonl.enc";

// LogEntry is now imported from kprotect_common

pub struct EncryptedLogger {
    events_file: Arc<Mutex<File>>,
    audit_file: Arc<Mutex<File>>,
    key: [u8; 32],
}

impl EncryptedLogger {
    pub fn new(key: [u8; 32]) -> Result<Self> {
        // Ensure log directory exists
        if let Some(parent) = Path::new(EVENTS_LOG_PATH).parent() {
            std::fs::create_dir_all(parent)?;
        }

        // Open or create log files in append mode
        let events_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(EVENTS_LOG_PATH)
            .context("Failed to open events log file")?;

        let audit_file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(AUDIT_LOG_PATH)
            .context("Failed to open audit log file")?;

        // Set file permissions to 0600 (owner read/write only)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let permissions = std::fs::Permissions::from_mode(0o600);
            std::fs::set_permissions(EVENTS_LOG_PATH, permissions.clone())?;
            std::fs::set_permissions(AUDIT_LOG_PATH, permissions)?;
        }

        Ok(Self {
            events_file: Arc::new(Mutex::new(events_file)),
            audit_file: Arc::new(Mutex::new(audit_file)),
            key,
        })
    }

    /// Log a security event (BLOCK/VERIFIED/BIRTH/EXIT)
    pub fn log_security_event(
        &self,
        event_id: u64,
        event: &BridgeEvent,
        comm: &str,
        target: &str,
        chain: Vec<String>,
        authorized: bool,
        complete: bool,
    ) -> Result<()> {
        let entry = LogEntry::SecurityEvent {
            id: event_id,
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            status: if !authorized {
                "Blocked".to_string()
            } else {
                match event.event_type {
                    1 => "Verified".to_string(),
                    2 => "Blocked".to_string(), // Event type 2 now also maps to Blocked if authorized is false, otherwise it's treated as Blocked.
                    3 => "Birth".to_string(),
                    4 => "Exit".to_string(),
                    _ => "Unknown".to_string(),
                }
            },
            pid: event.pid,
            comm: comm.to_string(),
            target: target.to_string(),
            chain,
            signature: format!("0x{:x}", event.signature),
            authorized,
            complete,
        };

        let mut file = self.events_file.lock().unwrap();
        self.write_encrypted_line(&mut file, &entry)
    }

    /// Log an audit action (AUTHORIZE/REVOKE/CONFIG changes)
    pub fn log_audit(
        &self,
        action: &str,
        user: &str,
        details: serde_json::Value,
        success: bool,
    ) -> Result<()> {
        let entry = LogEntry::AuditAction {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)?
                .as_secs(),
            action: action.to_string(),
            username: user.to_string(),
            details,
            success,
        };

        let mut file = self.audit_file.lock().unwrap();
        self.write_encrypted_line(&mut file, &entry)
    }

    /// Read security events with pagination
    pub fn read_events(&self, count: usize, offset: usize) -> Result<Vec<LogEntry>> {
        self.read_encrypted_lines(EVENTS_LOG_PATH, count, offset)
    }

    /// Read audit logs with pagination
    pub fn read_audit(&self, count: usize, offset: usize) -> Result<Vec<LogEntry>> {
        self.read_encrypted_lines(AUDIT_LOG_PATH, count, offset)
    }


    /// Clean up old security events
    pub fn cleanup_events(&self, retention_days: u32) -> Result<()> {
        self.cleanup_old_entries(EVENTS_LOG_PATH, retention_days)
    }

    /// Clean up old audit entries
    pub fn cleanup_audit(&self, retention_days: u32) -> Result<()> {
        self.cleanup_old_entries(AUDIT_LOG_PATH, retention_days)
    }

    /// Get the maximum event ID currently in the log
    pub fn get_max_event_id(&self) -> u64 {
        // Read the last 50 events and find the max ID
        self.read_events(50, 0).unwrap_or_default().iter().filter_map(|entry| {
            if let LogEntry::SecurityEvent { id, .. } = entry {
                Some(*id)
            } else {
                None
            }
        }).max().unwrap_or(0)
    }

    // Private helper methods

    fn write_encrypted_line(&self, file: &mut File, entry: &LogEntry) -> Result<()> {
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
            .context("Failed to serialize log entry")?;

        // Encrypt
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| anyhow!("Invalid encryption key"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let ciphertext = cipher
            .encrypt(nonce, json.as_bytes())
            .map_err(|_| anyhow!("Encryption failed"))?;

        // Write: timestamp:nonce:ciphertext
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

    fn decrypt_line(&self, line: &str) -> Result<LogEntry> {
        let parts: Vec<&str> = line.split(':').collect();
        if parts.len() != 3 {
            bail!("Invalid log line format");
        }

        let _timestamp = parts[0]
            .parse::<u64>()
            .context("Invalid timestamp")?;
        let nonce_bytes = hex::decode(parts[1])
            .context("Invalid nonce hex")?;
        let ciphertext = hex::decode(parts[2])
            .context("Invalid ciphertext hex")?;

        // Decrypt
        let cipher = Aes256Gcm::new_from_slice(&self.key)
            .map_err(|_| anyhow!("Invalid encryption key"))?;
        let nonce = Nonce::from_slice(&nonce_bytes);
        let plaintext = cipher
            .decrypt(nonce, ciphertext.as_ref())
            .map_err(|_| anyhow!("Decryption failed"))?;

        let json = String::from_utf8(plaintext)
            .context("Invalid UTF-8 in decrypted data")?;
        let entry: LogEntry = serde_json::from_str(&json)
            .context("Failed to parse log entry JSON")?;

        Ok(entry)
    }

    fn read_encrypted_lines(&self, path: &str, count: usize, offset: usize) -> Result<Vec<LogEntry>> {
        if !Path::new(path).exists() {
            return Ok(vec![]);
        }

        let file = File::open(path)
            .context("Failed to open log file")?;
        let reader = BufReader::new(file);

        // For now, we still read into memory but support pagination properly
        // In a future optimization, we can use reverse seeking to avoid loading everything
        let lines: Vec<String> = reader
            .lines()
            .filter_map(|l| l.ok())
            .collect();

        let mut entries = Vec::new();
        // Skip 'offset' lines from the end, then take 'count' lines
        for line in lines.iter().rev().skip(offset).take(count) {
            if let Ok(entry) = self.decrypt_line(line) {
                entries.push(entry);
            }
        }

        Ok(entries)
    }

    fn cleanup_old_entries(&self, path: &str, retention_days: u32) -> Result<()> {
        if !Path::new(path).exists() {
            return Ok(());
        }

        let cutoff = SystemTime::now()
            .duration_since(UNIX_EPOCH)?
            .as_secs()
            - (retention_days as u64 * 86400);

        let file = File::open(path)?;
        let reader = BufReader::new(file);

        let mut kept_lines = Vec::new();

        // Fast scan: only check timestamps (no decryption!)
        for line in reader.lines() {
            let line = line?;
            if let Some(timestamp_str) = line.split(':').next() {
                if let Ok(timestamp) = timestamp_str.parse::<u64>() {
                    if timestamp >= cutoff {
                        kept_lines.push(line);
                    }
                }
            }
        }

        // Rewrite file with only recent entries
        let mut file = File::create(path)?;
        for line in kept_lines {
            writeln!(file, "{}", line)?;
        }

        Ok(())
    }
}
