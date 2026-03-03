use crate::core::auth::{parse_pattern, truncate_zone_pattern};
use crate::core::domain::PatternType;
use crate::crypto;
use crate::migration::ZonesFile;
use anyhow::{Context, Result};
use kprotect_common::AuthorizedPattern;
use std::ffi::CString;

pub const ZONES_ENC: &str = "/var/lib/kprotect/configs/zones.enc";
pub const ENRICHMENT_ENC: &str = "/var/lib/kprotect/configs/enrichment.enc";
pub const AUTHORIZED_PATTERNS_PATH: &str = "/var/lib/kprotect/configs/authorized_patterns.enc";
pub const NOTIFICATION_RULES_PATH: &str = "/var/lib/kprotect/configs/notifications.enc";
pub const SUDO_RULES_PATH: &str = "/var/lib/kprotect/configs/sudo_patterns.enc";
pub const MAX_RED_ZONE_PATTERNS: usize = 192;
pub const MAX_ENRICHMENT_PATTERNS: usize = 32;

pub const SYSTEM_ENRICHMENT_PATTERNS: &[&str] = &[
    "/usr/bin/sudo*",
    "/usr/bin/sudoedit*",
    "/usr/bin/pkexec*",
    "/bin/sudo*",
    "/usr/sbin/sudo*",
];

pub fn get_username_from_uid(uid: u32) -> String {
    unsafe {
        let pw = libc::getpwuid(uid);
        if !pw.is_null() {
            if let Ok(name_str) = std::ffi::CStr::from_ptr((*pw).pw_name).to_str() {
                return name_str.to_string();
            }
        }
    }
    format!("{}", uid)
}

pub fn is_user_in_group(uid: u32, group_name: &str) -> bool {
    if uid == 0 {
        return true;
    }
    let uid_nix = nix::unistd::Uid::from_raw(uid);
    let user = match nix::unistd::User::from_uid(uid_nix) {
        Ok(Some(u)) => u,
        _ => return false,
    };
    let target_gid = match nix::unistd::Group::from_name(group_name) {
        Ok(Some(g)) => g.gid,
        _ => return false,
    };
    if user.gid == target_gid {
        return true;
    }
    let user_name_c = match CString::new(user.name) {
        Ok(s) => s,
        Err(_) => return false,
    };
    if let Ok(groups) = nix::unistd::getgrouplist(&user_name_c, user.gid) {
        for gid in groups {
            if gid == target_gid {
                return true;
            }
        }
    }
    false
}

pub fn save_authorized_patterns(patterns: &Vec<AuthorizedPattern>, key: &[u8; 32]) -> Result<()> {
    crypto::save_encrypted(patterns, AUTHORIZED_PATTERNS_PATH, key)
        .context("Failed to save authorized patterns")
}

pub async fn read_zones_file(key: &[u8; 32]) -> Result<ZonesFile> {
    tokio::task::block_in_place(|| {
        crypto::load_encrypted(ZONES_ENC, key).context("Failed to load encrypted zones")
    })
}

pub async fn add_zone_to_file(pattern: &str, key: &[u8; 32]) -> Result<String> {
    let mut zones = read_zones_file(key).await?;
    let _ = parse_pattern(pattern)?;
    let final_pattern = truncate_zone_pattern(pattern);
    if zones.red_zones.contains(&final_pattern.to_string()) {
        anyhow::bail!("Pattern already exists");
    }
    if zones.red_zones.len() >= MAX_RED_ZONE_PATTERNS {
        anyhow::bail!(
            "Red zone limit reached ({} patterns max)",
            MAX_RED_ZONE_PATTERNS
        );
    }
    zones.red_zones.push(final_pattern.clone());
    tokio::task::block_in_place(|| crypto::save_encrypted(&zones, ZONES_ENC, key))?;
    Ok(final_pattern)
}

pub async fn remove_zone_from_file(pattern: &str, key: &[u8; 32]) -> Result<bool> {
    let mut zones = read_zones_file(key).await?;
    let initial_len = zones.red_zones.len();
    zones.red_zones.retain(|p| p != pattern);
    if zones.red_zones.len() == initial_len {
        return Ok(false);
    }
    tokio::task::block_in_place(|| crypto::save_encrypted(&zones, ZONES_ENC, key))?;
    Ok(true)
}

pub async fn read_enrichment_patterns_file(key: &[u8; 32]) -> Result<Vec<String>> {
    let patterns: Vec<String> = tokio::task::block_in_place(|| {
        crypto::load_encrypted(ENRICHMENT_ENC, key)
            .context("Failed to load encrypted enrichment patterns")
    })
    .unwrap_or_default();

    // Always pre-pend system patterns for visibility
    let mut all_patterns = Vec::new();
    for sys in SYSTEM_ENRICHMENT_PATTERNS {
        all_patterns.push(sys.to_string());
    }
    all_patterns.extend(patterns);
    Ok(all_patterns)
}

pub async fn add_enrichment_pattern_to_file(pattern: &str, key: &[u8; 32]) -> Result<()> {
    let mut patterns = read_enrichment_patterns_file(key).await?;
    if patterns.contains(&pattern.to_string()) {
        anyhow::bail!("Pattern already exists");
    }
    if !pattern.ends_with('*') {
        anyhow::bail!("Enrichment pattern must end with '*' (e.g. /usr/bin/python*)");
    }
    match parse_pattern(pattern) {
        Ok(PatternType::Prefix(_)) => {}
        _ => anyhow::bail!("Enrichment pattern must be a valid prefix pattern (* at end only)"),
    }
    patterns.push(pattern.to_string());
    tokio::task::block_in_place(|| crypto::save_encrypted(&patterns, ENRICHMENT_ENC, key))?;
    Ok(())
}

pub async fn remove_enrichment_pattern_from_file(pattern: &str, key: &[u8; 32]) -> Result<bool> {
    // Prevent removal of system patterns
    if SYSTEM_ENRICHMENT_PATTERNS.contains(&pattern) {
        anyhow::bail!(
            "PROTECTED: Cannot remove system-required pattern: {}",
            pattern
        );
    }

    let mut patterns = read_enrichment_patterns_file(key).await?;
    let initial_len = patterns.len();
    patterns.retain(|p| p != pattern);
    if patterns.len() == initial_len {
        return Ok(false);
    }
    tokio::task::block_in_place(|| crypto::save_encrypted(&patterns, ENRICHMENT_ENC, key))?;
    Ok(true)
}

pub fn save_notification_rules(
    rules: &Vec<kprotect_common::NotificationRule>,
    key: &[u8; 32],
) -> Result<()> {
    crypto::save_encrypted(rules, NOTIFICATION_RULES_PATH, key)
        .context("Failed to save notification rules")
}

pub fn save_sudo_rules(rules: &Vec<kprotect_common::SudoRule>, key: &[u8; 32]) -> Result<()> {
    crypto::save_encrypted(rules, SUDO_RULES_PATH, key).context("Failed to save sudo rules")
}

pub async fn clear_zones_file(key: &[u8; 32]) -> Result<()> {
    let zones = ZonesFile {
        green_zones: vec![],
        red_zones: vec![],
    };
    tokio::task::block_in_place(|| crypto::save_encrypted(&zones, ZONES_ENC, key))?;
    Ok(())
}

pub async fn clear_enrichment_patterns_file(key: &[u8; 32]) -> Result<()> {
    let patterns: Vec<String> = vec![];
    tokio::task::block_in_place(|| crypto::save_encrypted(&patterns, ENRICHMENT_ENC, key))?;
    Ok(())
}

pub fn fnv1a_hash(data: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in data {
        if b == 0 {
            break;
        }
        h ^= b as u64;
        h = h.wrapping_mul(0x100000001b3);
    }
    h
}
