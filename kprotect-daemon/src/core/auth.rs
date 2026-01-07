use std::collections::HashMap;
use kprotect_common::{AuthorizedPattern, MatchMode};
use log::info;
use anyhow::{Result, Context, bail};
use aya::maps::lpm_trie::{LpmTrie, Key};
use aya::maps::MapData;

use crate::core::domain::{ChainTrieNode, PatternType, PathKey, LPM_KEY_SIZE};

/// Parse a pattern string into PatternType
/// Rules:
/// - "*" only at start OR end, never both, never in the middle
/// - No "*" = exact match
pub fn parse_pattern(pattern: &str) -> Result<PatternType> {
    let asterisk_count = pattern.matches('*').count();
    
    if asterisk_count == 0 {
        // Exact match
        return Ok(PatternType::Exact(pattern.to_string()));
    }
    
    if asterisk_count > 1 {
        bail!("Invalid pattern '{}': only single asterisk allowed at start or end", pattern);
    }
    
    // Single asterisk
    if pattern.starts_with('*') {
        // Suffix match: "*.env" -> ".env"
        let suffix = &pattern[1..];
        if suffix.contains('*') {
            bail!("Invalid pattern '{}': asterisk must be at start or end only", pattern);
        }
        return Ok(PatternType::Suffix(suffix.to_string()));
    }
    
    if pattern.ends_with('*') {
        // Prefix match: "/usr/*" -> "/usr/"
        let prefix = &pattern[..pattern.len() - 1];
        if prefix.contains('*') {
            bail!("Invalid pattern '{}': asterisk must be at start or end only", pattern);
        }
        return Ok(PatternType::Prefix(prefix.to_string()));
    }
    
    bail!("Invalid pattern '{}': asterisk must be at start or end", pattern);
}

/// Truncate a pattern for matching limits (LPM_KEY_SIZE)
pub fn truncate_zone_pattern(pattern: &str) -> String {
    if pattern.starts_with('*') {
        let suffix = &pattern[1..];
        if suffix.len() > LPM_KEY_SIZE {
            format!("*{}", &suffix[..LPM_KEY_SIZE])
        } else {
            pattern.to_string()
        }
    } else if pattern.ends_with('*') {
        let prefix = &pattern[..pattern.len() - 1];
        if prefix.len() > LPM_KEY_SIZE {
            format!("{}*", &prefix[..LPM_KEY_SIZE])
        } else {
            pattern.to_string()
        }
    } else {
        if pattern.len() > LPM_KEY_SIZE {
            pattern[..LPM_KEY_SIZE].to_string()
        } else {
            pattern.to_string()
        }
    }
}

/// Insert a prefix pattern into LPM Trie
pub fn insert_prefix<T: std::borrow::BorrowMut<MapData>>(
    map: &mut LpmTrie<T, PathKey, u8>,
    prefix: &str,
) -> Result<()> {
    let bytes = prefix.as_bytes();
    let len = bytes.len().min(LPM_KEY_SIZE);
    
    let mut key_data = [0u8; LPM_KEY_SIZE];
    key_data[..len].copy_from_slice(&bytes[..len]);
    
    // prefix_len is in BITS
    let key = Key::new((len * 8) as u32, PathKey { data: key_data });
    map.insert(&key, 1, 0)?;
    
    Ok(())
}

/// Insert a suffix pattern into LPM Trie (reversed)
pub fn insert_suffix<T: std::borrow::BorrowMut<MapData>>(
    map: &mut LpmTrie<T, PathKey, u8>,
    suffix: &str,
) -> Result<()> {
    let bytes = suffix.as_bytes();
    let len = bytes.len().min(LPM_KEY_SIZE);
    
    // Reverse the suffix for LPM matching
    let mut key_data = [0u8; LPM_KEY_SIZE];
    for i in 0..len {
        key_data[i] = bytes[len - 1 - i];
    }
    
    // prefix_len is in BITS
    let key = Key::new((len * 8) as u32, PathKey { data: key_data });
    map.insert(&key, 1, 0)?;
    
    Ok(())
}

/// Remove a prefix pattern from LPM Trie
pub fn remove_prefix<T: std::borrow::BorrowMut<MapData>>(
    map: &mut LpmTrie<T, PathKey, u8>,
    prefix: &str,
) -> Result<()> {
    let bytes = prefix.as_bytes();
    let len = bytes.len().min(LPM_KEY_SIZE);
    
    let mut key_data = [0u8; LPM_KEY_SIZE];
    key_data[..len].copy_from_slice(&bytes[..len]);
    
    let key = Key::new((len * 8) as u32, PathKey { data: key_data });
    map.remove(&key)?;
    
    Ok(())
}

/// Remove a suffix pattern from LPM Trie (reversed)
pub fn remove_suffix<T: std::borrow::BorrowMut<MapData>>(
    map: &mut LpmTrie<T, PathKey, u8>,
    suffix: &str,
) -> Result<()> {
    let bytes = suffix.as_bytes();
    let len = bytes.len().min(LPM_KEY_SIZE);
    
    let mut key_data = [0u8; LPM_KEY_SIZE];
    for i in 0..len {
        key_data[i] = bytes[len - 1 - i];
    }
    
    let key = Key::new((len * 8) as u32, PathKey { data: key_data });
    map.remove(&key)?;
    
    Ok(())
}

/// Rebuild optimized authorization caches from master patterns list
pub fn rebuild_auth_caches(authorized_patterns: &[AuthorizedPattern], exact_cache: &mut HashMap<Vec<String>, AuthorizedPattern>, suffix_cache: &mut ChainTrieNode) {
    exact_cache.clear();
    *suffix_cache = ChainTrieNode::new();

    for pattern in authorized_patterns {
        match pattern.match_mode {
            MatchMode::Exact => {
                exact_cache.insert(pattern.pattern.clone(), pattern.clone());
            }
            MatchMode::Suffix => {
                // To maintain Trie prefix sharing for suffixes, we REVERSE the pattern
                let mut reversed_pattern = pattern.pattern.clone();
                reversed_pattern.reverse();
                suffix_cache.insert(&reversed_pattern, pattern.clone());
            }
        }
    }
    info!("🔄 Authorization caches rebuilt: {} exact, {} suffix patterns", 
          exact_cache.len(), authorized_patterns.len() - exact_cache.len());
}

/// Check if a process chain matches any authorized pattern
pub fn is_chain_authorized(chain: &[String], exact_cache: &HashMap<Vec<String>, AuthorizedPattern>, suffix_cache: &ChainTrieNode) -> bool {
    // 1. O(1) Exact Match lookup
    if let Some(pattern) = exact_cache.get(chain) {
        info!("✅ Chain matched Exact pattern: {:?} (description: {:?})", 
              pattern.pattern, pattern.description);
        return true;
    }

    // 2. O(m) Suffix Match lookup using reversed Trie
    let mut reversed_chain = chain.to_vec();
    reversed_chain.reverse();
    
    // We need to check all possible lengths for the suffix in the Trie
    // Actually, the Trie traversal should find the longest prefix of the reversed chain
    // that is marked as terminal.
    
    let mut current = suffix_cache;
    for part in reversed_chain {
        if let Some(next) = current.children.get(&part) {
            current = next;
            if current.is_terminal {
                if let Some(pattern) = &current.pattern {
                    info!("✅ Chain matched Suffix pattern: {:?} (description: {:?})", 
                          pattern.pattern, pattern.description);
                    return true;
                }
            }
        } else {
            break;
        }
    }

    false
}
