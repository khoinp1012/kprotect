use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use kprotect_common::AuthorizedPattern;
use aya::Pod;

#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct LineageNode {
    pub path: String,
    pub arg: Option<String>,
    pub ppid: u32,
    pub start_time: u64,
    pub signature: u64,
    pub child_count: u32,  // Number of living children
    pub is_exited: bool,   // Has the process exited?
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EnrichmentFile {
    pub enrichment_patterns: Vec<String>,
}

/// Pattern type after parsing
#[derive(Debug, Clone)]
pub enum PatternType {
    Prefix(String),  // "/usr/*" -> "/usr/"
    Suffix(String),  // "*.env" -> ".env"
    Exact(String),   // "/etc/passwd" -> "/etc/passwd"
}

/// Suffix matching Trie for lineage chains
#[derive(Debug, Default)]
pub struct ChainTrieNode {
    pub children: HashMap<String, ChainTrieNode>,
    pub is_terminal: bool,
    pub pattern: Option<AuthorizedPattern>,
}

impl ChainTrieNode {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn insert(&mut self, chain: &[String], pattern: AuthorizedPattern) {
        let mut current = self;
        for part in chain {
            current = current.children.entry(part.clone()).or_insert_with(ChainTrieNode::new);
        }
        current.is_terminal = true;
        current.pattern = Some(pattern);
    }
}

// eBPF Limits (MUST match eBPF side!)
pub const LPM_KEY_SIZE: usize = 32;

/// LPM Trie Key for path matching (must match eBPF side)
#[repr(C)]
#[derive(Clone, Copy, Debug)]
pub struct PathKey {
    pub data: [u8; LPM_KEY_SIZE],
}

// SAFETY: PathKey is repr(C) and contains only u8 arrays
unsafe impl Pod for PathKey {}
