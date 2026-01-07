use crate::crypto;
use crate::logger::EncryptedLogger;
use anyhow::{Context, Result};
use log::info;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::Path;


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct ZonesFile {
    #[serde(default)]
    pub green_zones: Vec<String>,
    pub red_zones: Vec<String>,
}

// Encrypted config paths
const ENCRYPTED_DIR: &str = "/var/lib/kprotect/configs";
const ZONES_ENC: &str = "/var/lib/kprotect/configs/zones.enc";
const ENRICHMENT_ENC: &str = "/var/lib/kprotect/configs/enrichment.enc";

/// Initialize encrypted configs with defaults if they don't exist
pub fn ensure_encrypted_configs(key: &[u8; 32], logger: &EncryptedLogger) -> Result<()> {
    info!("🔄 Checking configuration files...");
    
    // Create encrypted config directory
    fs::create_dir_all(ENCRYPTED_DIR)
        .context("Failed to create encrypted config directory")?;
    
    // NOTE: authorized_patterns.enc is created on-demand when patterns are added
    // No need to pre-create it here
    
    // 1. Initialize zones.enc
    if !Path::new(ZONES_ENC).exists() {
        info!("  Creating default zones...");
        let default_zones = ZonesFile { 
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
        crypto::save_encrypted(&default_zones, ZONES_ENC, key)?;
        
        // Audit log: default config created
        let _ = logger.log_audit(
            "INIT_DEFAULT_CONFIG",
            "system",
            serde_json::json!({
                "config_file": "zones.enc",
                "red_zones_count": default_zones.red_zones.len(),
                "reason": "first_start"
            }),
            true
        );
        
        info!("  ✅ Default zones created");
    }
    
    // 2. Initialize enrichment.enc
    if !Path::new(ENRICHMENT_ENC).exists() {
        info!("  Creating default enrichment patterns...");
        let default_patterns = vec![
            "/usr/bin/python*".to_string(),   // Prefix match for system python
            "/bin/python*".to_string(),       // Prefix match for /bin python
            "/usr/bin/node*".to_string(),     // Prefix match for system node
            "/bin/node*".to_string(),         // Prefix match for /bin node
            "*/bin/bash".to_string(),         // Suffix match
            "*/bin/sh".to_string(),           // Suffix match
            "*/bin/zsh".to_string(),          // Suffix match
            "*/bin/ruby".to_string(),         // Suffix match
            "*/bin/perl".to_string(),         // Suffix match
            "*/bin/php".to_string(),          // Suffix match
        ];
        
        crypto::save_encrypted(&default_patterns, ENRICHMENT_ENC, key)?;
        
        // Audit log: default config created
        let _ = logger.log_audit(
            "INIT_DEFAULT_CONFIG",
            "system",
            serde_json::json!({
                "config_file": "enrichment.enc",
                "patterns_count": default_patterns.len(),
                "reason": "first_start"
            }),
            true
        );
        
        info!("  ✅ Default enrichment patterns created ({} entries)", default_patterns.len());
    }
    
    info!("✅ Configuration preparation complete!");
    Ok(())
}
