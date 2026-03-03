use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};

/// Configuration for path matching loaded from JSON
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PathConfig {
    pub whitelist: Vec<String>,
    pub blacklist: Vec<String>,
}

#[derive(Debug, Clone, Default)]
struct TrieNode {
    children: HashMap<char, TrieNode>,
    is_end_of_pattern: bool,
}


#[derive(Debug, Clone, Default)]
struct Trie {
    root: TrieNode,
}

impl Trie {

    fn insert(&mut self, pattern: &str) {
        let mut node = &mut self.root;
        for c in pattern.chars() {
            node = node.children.entry(c).or_default();
        }
        node.is_end_of_pattern = true;
    }

    /// Checks if the input string matches any prefix in the Trie.
    fn matches_prefix(&self, s: &str) -> bool {
        let mut node = &self.root;
        if node.is_end_of_pattern {
            return true;
        }
        for c in s.chars() {
            if let Some(n) = node.children.get(&c) {
                node = n;
                if node.is_end_of_pattern {
                    return true;
                }
            } else {
                return false;
            }
        }
        node.is_end_of_pattern
    }
}

/// Matches paths against a set of exact, prefix, and suffix patterns.
#[derive(Default)]
pub struct PathMatcher {
    exact: HashSet<String>,
    prefixes: Trie,
    suffixes: Trie, // Stores reversed patterns
}

impl PathMatcher {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_config(patterns: &[String]) -> Result<Self, String> {
        let mut matcher = Self::new();
        for pattern in patterns {
            matcher.add_rule(pattern)?;
        }
        Ok(matcher)
    }

    pub fn add_rule(&mut self, pattern: &str) -> Result<(), String> {
        if pattern.starts_with('~') {
            return Err(format!("Invalid pattern '{}': Patterns starting with ~ are not supported. Please use absolute paths or *.", pattern));
        }

        let asterisk_count = pattern.chars().filter(|&c| c == '*').count();
        if asterisk_count > 1 {
            return Err(format!(
                "Invalid pattern '{}': Multiple asterisks are not allowed.",
                pattern
            ));
        }

        if asterisk_count == 1 {
            if let Some(prefix) = pattern.strip_suffix('*') {
                self.prefixes.insert(prefix);
            } else if let Some(suffix) = pattern.strip_prefix('*') {
                let reversed: String = suffix.chars().rev().collect();
                self.suffixes.insert(&reversed);
            } else {
                return Err(format!(
                    "Invalid pattern '{}': Asterisk must be at the start or end.",
                    pattern
                ));
            }
        } else {
            // Exact match
            self.exact.insert(pattern.to_string());
        }
        Ok(())
    }

    pub fn matches(&self, path: &str) -> bool {
        if self.exact.contains(path) {
            return true;
        }

        if self.prefixes.matches_prefix(path) {
            return true;
        }

        let reversed_path: String = path.chars().rev().collect();
        if self.suffixes.matches_prefix(&reversed_path) {
            return true;
        }

        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_exact_match() {
        let mut matcher = PathMatcher::new();
        matcher.add_rule("/etc/passwd").unwrap();
        assert!(matcher.matches("/etc/passwd"));
        assert!(!matcher.matches("/etc/shadow"));
    }

    #[test]
    fn test_prefix_match() {
        let mut matcher = PathMatcher::new();
        matcher.add_rule("/usr/bin/*").unwrap();
        assert!(matcher.matches("/usr/bin/ls"));
        assert!(matcher.matches("/usr/bin/local/script"));
        assert!(matcher.matches("/usr/bin/"));
        assert!(!matcher.matches("/usr/bi"));
    }

    #[test]
    fn test_suffix_match() {
        let mut matcher = PathMatcher::new();
        matcher.add_rule("*.rs").unwrap();
        assert!(matcher.matches("lib.rs"));
        assert!(matcher.matches("/src/main.rs"));
        assert!(!matcher.matches("main.c"));
        assert!(!matcher.matches("rs"));
    }

    #[test]
    fn test_mixed_patterns() {
        let patterns = vec![
            "/exact/path".to_string(),
            "/prefix/*".to_string(),
            "*.suffix".to_string(),
        ];
        let matcher = PathMatcher::from_config(&patterns).unwrap();

        assert!(matcher.matches("/exact/path"));
        assert!(!matcher.matches("/exact/path/extra"));

        assert!(matcher.matches("/prefix/file"));
        assert!(matcher.matches("/prefix/nested/file"));
        assert!(!matcher.matches("/other/prefix/file"));

        assert!(matcher.matches("file.suffix"));
        assert!(matcher.matches("/path/to/file.suffix"));
        assert!(!matcher.matches("file.suffix.other"));
    }

    #[test]
    fn test_asterisk_match() {
        let mut matcher = PathMatcher::new();
        matcher.add_rule("*").unwrap();
        assert!(matcher.matches("/anything"));
        assert!(matcher.matches(""));
        assert!(matcher.matches("/etc/passwd"));
    }

    #[test]
    fn test_invalid_patterns() {
        let mut matcher = PathMatcher::new();
        assert!(matcher.add_rule("/bad/**").is_err());
        assert!(matcher.add_rule("/bad/*/pattern").is_err());
        assert!(matcher.add_rule("*.so.*").is_err());
        assert!(matcher.add_rule("normal/path").is_ok());
        assert!(matcher.add_rule("/prefix/*").is_ok());
        assert!(matcher.add_rule("*.suffix").is_ok());
    }
}
