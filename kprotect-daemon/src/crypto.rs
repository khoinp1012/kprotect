//! Cryptography utilities for kprotect
//!
//! Provides AES-256-GCM encryption/decryption with machine-derived keys

use aes_gcm::{
    aead::{Aead, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use anyhow::{Context, Result};
use hkdf::Hkdf;
use sha2::Sha256;
use std::fs;
use std::path::Path;

/// Salt file location
pub const SALT_PATH: &str = "/var/lib/kprotect/salt";

/// Ensure salt file exists, generate if needed
pub fn ensure_salt() -> Result<()> {
    let salt_dir = Path::new(SALT_PATH).parent().unwrap();
    
    // Create directory if needed
    fs::create_dir_all(salt_dir)
        .context("Failed to create /var/lib/kprotect directory")?;
    
    if !Path::new(SALT_PATH).exists() {
        log::info!("🔐 Generating new salt file...");
        
        // Generate random 32-byte salt
        let mut salt = [0u8; 32];
        use rand::RngCore;
        OsRng.fill_bytes(&mut salt);
        
        // Write salt file
        fs::write(SALT_PATH, &salt)
            .context("Failed to write salt file")?;
        
        // Set restrictive permissions (0400 - read-only for owner)
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(SALT_PATH, fs::Permissions::from_mode(0o400))
                .context("Failed to set salt file permissions")?;
        }
        
        log::info!("✅ Salt file created at {}", SALT_PATH);
    }
    
    Ok(())
}

/// Derive encryption key from salt + machine-specific data
pub fn derive_key() -> Result<[u8; 32]> {
    // Read salt
    let salt = fs::read(SALT_PATH)
        .context(format!("Failed to read salt from {}", SALT_PATH))?;
    
    if salt.len() != 32 {
        anyhow::bail!("Invalid salt size: {} bytes (expected 32)", salt.len());
    }
    
    // Read machine-specific sources
    let machine_id = fs::read_to_string("/etc/machine-id")
        .context("Failed to read /etc/machine-id")?;
    
    let hostname = fs::read_to_string("/etc/hostname")
        .unwrap_or_else(|_| "localhost".to_string());
    
    // Derive key using HKDF-SHA256
    let mut key = [0u8; 32];
    let hkdf = Hkdf::<Sha256>::new(Some(&salt), machine_id.as_bytes());
    hkdf.expand(hostname.as_bytes(), &mut key)
        .map_err(|e| anyhow::anyhow!("HKDF key derivation failed: {}", e))?;
    
    Ok(key)
}

/// Encrypt JSON data using AES-256-GCM
pub fn encrypt_json<T: serde::Serialize>(data: &T, key: &[u8; 32]) -> Result<Vec<u8>> {
    // Serialize to JSON
    let json = serde_json::to_string_pretty(data)
        .context("Failed to serialize to JSON")?;
    
    // Create cipher
    let cipher = Aes256Gcm::new(key.into());
    
    // Generate random nonce (12 bytes for GCM)
    let mut nonce_bytes = [0u8; 12];
    use rand::RngCore;
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);
    
    // Encrypt
    let ciphertext = cipher.encrypt(nonce, json.as_bytes())
        .map_err(|e| anyhow::anyhow!("Encryption failed: {}", e))?;
    
    // Return: nonce || ciphertext (with auth tag)
    let mut result = nonce_bytes.to_vec();
    result.extend_from_slice(&ciphertext);
    
    Ok(result)
}

/// Decrypt JSON data using AES-256-GCM
pub fn decrypt_json<T: serde::de::DeserializeOwned>(encrypted: &[u8], key: &[u8; 32]) -> Result<T> {
    if encrypted.len() < 12 {
        anyhow::bail!("Invalid encrypted data: too short (minimum 12 bytes for nonce)");
    }
    
    // Split nonce and ciphertext
    let (nonce_bytes, ciphertext) = encrypted.split_at(12);
    let nonce = Nonce::from_slice(nonce_bytes);
    
    // Create cipher
    let cipher = Aes256Gcm::new(key.into());
    
    // Decrypt
    let plaintext = cipher.decrypt(nonce, ciphertext)
        .map_err(|e| anyhow::anyhow!("Decryption failed (wrong key or tampered data): {}", e))?;
    
    // Parse JSON
    let data = serde_json::from_slice(&plaintext)
        .context("Failed to parse decrypted JSON")?;
    
    Ok(data)
}

/// Encrypt and save JSON to file
pub fn save_encrypted<T: serde::Serialize>(data: &T, path: &str, key: &[u8; 32]) -> Result<()> {
    let encrypted = encrypt_json(data, key)?;
    
    // Atomic write
    let temp_path = format!("{}.tmp", path);
    fs::write(&temp_path, &encrypted)
        .context(format!("Failed to write encrypted file: {}", temp_path))?;
    
    // Set restrictive permissions
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&temp_path, fs::Permissions::from_mode(0o600))
            .context("Failed to set file permissions")?;
    }
    
    // Atomic rename
    fs::rename(&temp_path, path)
        .context(format!("Failed to rename to {}", path))?;
    
    Ok(())
}

/// Load and decrypt JSON from file
pub fn load_encrypted<T: serde::de::DeserializeOwned>(path: &str, key: &[u8; 32]) -> Result<T> {
    let encrypted = fs::read(path)
        .context(format!("Failed to read encrypted file: {}", path))?;
    
    decrypt_json(&encrypted, key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde::{Deserialize, Serialize};
    
    #[derive(Serialize, Deserialize, PartialEq, Debug)]
    struct TestData {
        name: String,
        value: u32,
    }
    
    #[test]
    fn test_encrypt_decrypt() {
        let key = [42u8; 32];
        let data = TestData {
            name: "test".to_string(),
            value: 123,
        };
        
        let encrypted = encrypt_json(&data, &key).unwrap();
        let decrypted: TestData = decrypt_json(&encrypted, &key).unwrap();
        
        assert_eq!(data, decrypted);
    }
    
    #[test]
    fn test_wrong_key_fails() {
        let key1 = [1u8; 32];
        let key2 = [2u8; 32];
        
        let data = TestData {
            name: "test".to_string(),
            value: 123,
        };
        
        let encrypted = encrypt_json(&data, &key1).unwrap();
        let result: Result<TestData> = decrypt_json(&encrypted, &key2);
        
        assert!(result.is_err());
    }
    
    #[test]
    fn test_tampering_fails() {
        let key = [42u8; 32];
        let data = TestData {
            name: "test".to_string(),
            value: 123,
        };
        
        let mut encrypted = encrypt_json(&data, &key).unwrap();
        
        // Tamper with ciphertext
        if encrypted.len() > 20 {
            encrypted[20] ^= 0xFF;
        }
        
        let result: Result<TestData> = decrypt_json(&encrypted, &key);
        assert!(result.is_err());
    }
}
