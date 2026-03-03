use anyhow::{bail, Result};
use aya::maps::lpm_trie::{Key, LpmTrie};
use aya::maps::MapData;
use kprotect_common::{AuthorizedPattern, MatchMode};
use log::info;
use std::collections::HashMap;

use crate::core::domain::{ChainTrieNode, PathKey, PatternType, LPM_KEY_SIZE};

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
        bail!(
            "Invalid pattern '{}': only single asterisk allowed at start or end",
            pattern
        );
    }

    // Single asterisk
    if let Some(suffix) = pattern.strip_prefix('*') {
        // Suffix match: "*.env" -> ".env"
        if suffix.contains('*') {
            bail!(
                "Invalid pattern '{}': asterisk must be at start or end only",
                pattern
            );
        }
        return Ok(PatternType::Suffix(suffix.to_string()));
    }

    if let Some(prefix) = pattern.strip_suffix('*') {
        // Prefix match: "/usr/*" -> "/usr/"
        if prefix.contains('*') {
            bail!(
                "Invalid pattern '{}': asterisk must be at start or end only",
                pattern
            );
        }
        return Ok(PatternType::Prefix(prefix.to_string()));
    }

    bail!(
        "Invalid pattern '{}': asterisk must be at start or end",
        pattern
    );
}

/// Truncate a pattern for matching limits (LPM_KEY_SIZE)
pub fn truncate_zone_pattern(pattern: &str) -> String {
    if let Some(suffix) = pattern.strip_prefix('*') {
        if suffix.len() > LPM_KEY_SIZE {
            format!("*{}", &suffix[..LPM_KEY_SIZE])
        } else {
            pattern.to_string()
        }
    } else if let Some(prefix) = pattern.strip_suffix('*') {
        if prefix.len() > LPM_KEY_SIZE {
            format!("{}*", &prefix[..LPM_KEY_SIZE])
        } else {
            pattern.to_string()
        }
    } else if pattern.len() > LPM_KEY_SIZE {
        pattern[..LPM_KEY_SIZE].to_string()
    } else {
        pattern.to_string()
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
pub fn rebuild_auth_caches(
    authorized_patterns: &[AuthorizedPattern],
    exact_cache: &mut HashMap<Vec<String>, AuthorizedPattern>,
    suffix_cache: &mut ChainTrieNode,
) {
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
    info!(
        "🔄 Authorization caches rebuilt: {} exact, {} suffix patterns",
        exact_cache.len(),
        authorized_patterns.len() - exact_cache.len()
    );
}

/// Check if a process chain matches any authorized pattern
pub fn is_chain_authorized(
    chain: &[String],
    exact_cache: &HashMap<Vec<String>, AuthorizedPattern>,
    suffix_cache: &ChainTrieNode,
) -> Option<AuthorizedPattern> {
    // 1. O(1) Exact Match lookup
    if let Some(pattern) = exact_cache.get(chain) {
        info!(
            "✅ Chain matched Exact pattern: {:?} (description: {:?})",
            pattern.pattern, pattern.description
        );
        return Some(pattern.clone());
    }

    // 2. O(m) Suffix Match lookup using reversed Trie
    let mut reversed_chain = chain.to_vec();
    reversed_chain.reverse();

    let mut current = suffix_cache;
    for part in reversed_chain {
        if let Some(next) = current.children.get(&part) {
            current = next;
            if current.is_terminal {
                if let Some(pattern) = &current.pattern {
                    info!(
                        "✅ Chain matched Suffix pattern: {:?} (description: {:?})",
                        pattern.pattern, pattern.description
                    );
                    return Some(pattern.clone());
                }
            }
        } else {
            break;
        }
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_pattern_logic() {
        assert!(matches!(
            parse_pattern("/usr/bin/ls").unwrap(),
            PatternType::Exact(_)
        ));
        assert!(matches!(
            parse_pattern("*.so").unwrap(),
            PatternType::Suffix(_)
        ));
        assert!(matches!(
            parse_pattern("/usr/bin/*").unwrap(),
            PatternType::Prefix(_)
        ));

        // Invalid patterns
        assert!(parse_pattern("*/path/*").is_err());
        assert!(parse_pattern("*path*").is_err());
    }

    #[test]
    fn test_is_chain_authorized() {
        let mut exact_cache = HashMap::new();
        let mut suffix_cache = ChainTrieNode::new();

        let p1 = AuthorizedPattern {
            pattern: vec!["systemd".into(), "sshd".into(), "bash".into()],
            match_mode: MatchMode::Exact,
            description: "SSH Bash".into(),
            authorized_at: 0,
        };

        let p2 = AuthorizedPattern {
            pattern: vec!["bash".into(), "apt".into()],
            match_mode: MatchMode::Suffix,
            description: "Any Bash Apt".into(),
            authorized_at: 0,
        };

        let patterns = vec![p1, p2];
        rebuild_auth_caches(&patterns, &mut exact_cache, &mut suffix_cache);

        // Case 1: Exact Match
        let chain1 = vec![
            "systemd".to_string(),
            "sshd".to_string(),
            "bash".to_string(),
        ];
        let res1 = is_chain_authorized(&chain1, &exact_cache, &suffix_cache);
        assert!(res1.is_some());
        assert_eq!(res1.unwrap().description, "SSH Bash");

        // Case 2: Suffix Match
        let chain2 = vec!["other".to_string(), "bash".to_string(), "apt".to_string()];
        let res2 = is_chain_authorized(&chain2, &exact_cache, &suffix_cache);
        assert!(res2.is_some());
        assert_eq!(res2.unwrap().description, "Any Bash Apt");

        // Case 3: No Match
        let chain3 = vec!["systemd".to_string(), "bash".to_string()];
        let res3 = is_chain_authorized(&chain3, &exact_cache, &suffix_cache);
        assert!(res3.is_none());
    }
}
