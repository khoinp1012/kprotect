use anyhow::Result;
use aya::maps::perf::AsyncPerfEventArray;
use aya::maps::{HashMap as BpfHashMap, Map, MapData};
use aya::util::online_cpus;
use bytes::BytesMut;
use log::info;
use std::sync::atomic::Ordering;
use std::sync::Arc;
use tokio::sync::Mutex;

use kprotect_common::BridgeEvent;
// kprotect-daemon: eBPF Event Monitoring and Processing
// Copyright (C) 2026 khoinp1012
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU Affero General Public License as
// published by the Free Software Foundation, either version 3 of the
// License, or (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU Affero General Public License for more details.
//
// You should have received a copy of the GNU Affero General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

use crate::core::auth::is_chain_authorized;
use crate::core::domain::LineageNode;
use crate::core::process::{build_lineage_chain, cleanup_parent_chain};
use crate::state::AppState;

type AuthMap = Arc<Mutex<Option<BpfHashMap<MapData, u64, u8>>>>;
type SigMap = Arc<Mutex<Option<BpfHashMap<MapData, u32, u64>>>>;

pub async fn monitor_ebpf_events(
    map: Map,
    state: Arc<AppState>,
    auth_map: AuthMap,
    sig_map: SigMap,
) -> Result<()> {
    let mut perf_array = AsyncPerfEventArray::try_from(map)?;
    let cpus = online_cpus().map_err(|_| anyhow::anyhow!("CPUs error"))?;
    for cpu_id in cpus {
        // Increase buffer size to 512 pages (2MB) per CPU to prevent event drops during heavy load (Dolphin launch)
        let mut buf = perf_array.open(cpu_id, Some(512))?;
        let state_clone = state.clone();

        let auth_map_clone = auth_map.clone();
        let sig_map_clone = sig_map.clone();
        tokio::spawn(async move {
            // Processing batch size: 256 events
            let mut buffers = (0..256)
                .map(|_| BytesMut::with_capacity(4096))
                .collect::<Vec<_>>();
            while let Ok(events) = buf.read_events(&mut buffers).await {
                for (i, _) in buffers.iter().enumerate().take(events.read) {
                    let event = unsafe {
                        std::ptr::read_unaligned(buffers[i].as_ptr() as *const BridgeEvent)
                    };
                    let _ =
                        process_event(event, &state_clone, &auth_map_clone, &sig_map_clone).await;
                }
            }
        });
    }

    // Keep task alive
    std::future::pending::<()>().await;
    Ok(())
}

async fn process_event(
    event: BridgeEvent,
    state: &Arc<AppState>,
    auth_map: &AuthMap,
    _sig_map: &SigMap,
) -> Result<()> {
    // 1. Get configuration
    let (engine_enabled, file_protection_enabled) = {
        let rules = state.rules.read().unwrap();
        (
            rules.config.engine_enabled,
            rules.config.file_protection_enabled,
        )
    };

    // 2. Smart Suspend Check: If engine is disabled, only track Birth/Exit
    if !should_process_event(event.event_type, engine_enabled) {
        return Ok(());
    }

    let comm = bytes_to_string(&event.comm);
    let path = bytes_to_string(&event.path);

    match event.event_type {
        3 => handle_birth(event, state, auth_map, &comm, &path).await,
        4 => handle_exit(event, state).await,
        1 | 2 => handle_security_event(event, state, file_protection_enabled, &comm, &path).await,
        _ => Ok(()),
    }
}

async fn handle_birth(
    event: BridgeEvent,
    state: &Arc<AppState>,
    auth_map: &AuthMap,
    comm: &str,
    path: &str,
) -> Result<()> {
    let enriched_arg = parse_enriched_args(&event.arg, event.argc);
    let lineage_cache = state.lineage_cache.clone();

    // PID REUSE DETECTION
    if let Some(old_node) = lineage_cache.get(&event.pid) {
        if old_node.start_time != event.start_time {
            let old_ppid = old_node.ppid;
            drop(old_node);
            lineage_cache.remove(&event.pid);
            cleanup_parent_chain(&lineage_cache, old_ppid);
        }
    }

    // Sudo inheritance
    let sudo_ancestor = if let Some(parent) = lineage_cache.get(&event.ppid) {
        if parent.path == "/usr/bin/sudo" || parent.path.ends_with("/sudo") {
            Some(event.ppid)
        } else {
            parent.sudo_ancestor
        }
    } else {
        None
    };

    lineage_cache.insert(
        event.pid,
        LineageNode {
            path: if path.is_empty() {
                comm.to_string()
            } else {
                path.to_string()
            },
            arg: enriched_arg.clone(),
            ppid: event.ppid,
            start_time: event.start_time,
            signature: event.signature,
            child_count: 0,
            is_exited: false,
            sudo_ancestor,
        },
    );

    if let Some(mut parent) = lineage_cache.get_mut(&event.ppid) {
        parent.child_count += 1;
    }

    let (chain, _) = build_lineage_chain(event.pid, comm, path, &lineage_cache);

    let matched_pattern = {
        let rules = state.rules.read().unwrap();
        is_chain_authorized(&chain, &rules.auth_exact_cache, &rules.auth_suffix_cache)
    };

    if let Some(pattern) = matched_pattern {
        info!(
            "🛡️ Governor: Authorized PID {} ({}) due to pattern match: {}",
            event.pid,
            chain.join(" -> "),
            pattern.description
        );

        let mut auth_map_lock = auth_map.lock().await;
        if let Some(ref mut m) = *auth_map_lock {
            let _ = m.insert(event.signature, 1u8, 0u64);
        }
    }

    // Sudo monitoring logic
    if let Some(sudo_pid) = sudo_ancestor {
        if path != "/usr/bin/sudo" && path != "/usr/bin/sudoedit" {
            let is_authored = {
                if let Some(timestamp) = state.last_pam_elevations.get(&sudo_pid).map(|r| *r) {
                    let now = std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .unwrap()
                        .as_secs();
                    now - timestamp < 5
                } else {
                    false
                }
            };

            let status = if is_authored {
                "Sudo Launch (Authored)".to_string()
            } else {
                "Sudo Launch (Cached)".to_string()
            };
            let (chain, is_complete) =
                build_lineage_chain(event.pid, comm, path, &state.lineage_cache);
            let event_id = state.event_sequence.fetch_add(1, Ordering::SeqCst) + 1;
            let timestamp = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let entry = kprotect_common::LogEntry::SecurityEvent {
                id: event_id,
                timestamp,
                status: status.clone(),
                pid: event.pid,
                comm: comm.to_string(),
                target: if path.is_empty() {
                    comm.to_string()
                } else {
                    path.to_string()
                },
                chain,
                signature: format!("0x{:x}", event.signature),
                authorized: true,
                complete: is_complete,
                label_snapshot: vec![format!(
                    "{}: {} {}",
                    status,
                    path,
                    enriched_arg.unwrap_or_default()
                )],
            };

            let _ = state.logger.log_entry(&entry);
            let msg = serde_json::to_string(&entry).unwrap_or_default();
            let _ = state.event_tx.send(msg);
            let nm = state.notification_manager.clone();
            nm.match_and_dispatch(
                kprotect_common::EventTypeFilter::SudoVerified,
                "Sudo Bypass",
                serde_json::to_value(&entry).unwrap(),
            )
            .await;
        }
    }

    Ok(())
}

async fn handle_exit(event: BridgeEvent, state: &Arc<AppState>) -> Result<()> {
    let lineage_cache = state.lineage_cache.clone();
    if let Some(mut node) = lineage_cache.get_mut(&event.pid) {
        if node.start_time == event.start_time {
            node.is_exited = true;
            if node.child_count == 0 {
                let ppid = node.ppid;
                drop(node);
                lineage_cache.remove(&event.pid);
                state.last_pam_elevations.remove(&event.pid);
                cleanup_parent_chain(&lineage_cache, ppid);
            }
        }
    }
    Ok(())
}

enum SecurityVerdict {
    Authorized(Option<kprotect_common::AuthorizedPattern>),
    Blocked,
}

fn evaluate_security_logic(
    chain: &[String],
    file_protection_enabled: bool,
    exact_cache: &std::collections::HashMap<Vec<String>, kprotect_common::AuthorizedPattern>,
    suffix_cache: &crate::core::domain::ChainTrieNode,
) -> SecurityVerdict {
    if !file_protection_enabled {
        return SecurityVerdict::Authorized(None);
    }

    match is_chain_authorized(chain, exact_cache, suffix_cache) {
        Some(p) => SecurityVerdict::Authorized(Some(p)),
        None => SecurityVerdict::Blocked,
    }
}

async fn handle_security_event(
    event: BridgeEvent,
    state: &Arc<AppState>,
    file_protection_enabled: bool,
    comm: &str,
    path: &str,
) -> Result<()> {
    let (chain, is_complete) = build_lineage_chain(event.pid, comm, path, &state.lineage_cache);
    let chain_str = chain.join(" -> ");

    let verdict = {
        let rules = state.rules.read().unwrap();
        evaluate_security_logic(
            &chain,
            file_protection_enabled,
            &rules.auth_exact_cache,
            &rules.auth_suffix_cache,
        )
    };

    let (is_authorized, matched_pattern) = match verdict {
        SecurityVerdict::Authorized(p) => (true, p),
        SecurityVerdict::Blocked => (false, None),
    };

    let event_id = state.event_sequence.fetch_add(1, Ordering::SeqCst) + 1;
    if is_authorized {
        state.events_verified.fetch_add(1, Ordering::SeqCst);
    } else {
        state.events_blocked.fetch_add(1, Ordering::SeqCst);
    }

    let status_str = if is_authorized { "Verified" } else { "Blocked" };
    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let msg = serde_json::json!({
        "id": event_id,
        "timestamp": timestamp,
        "pid": event.pid,
        "signature": format!("0x{:x}", event.signature),
        "status": status_str,
        "comm": comm,
        "chain": chain,
        "chain_str": chain_str,
        "target": path,
        "authorized": is_authorized,
        "complete": is_complete
    })
    .to_string();

    println!(
        "{:<8} {:<4} {:<12} {:<15} {} -> {}",
        event.pid,
        event_id,
        status_str,
        comm,
        if is_authorized {
            "\x1b[32m[AUTHORIZED]\x1b[0m"
        } else {
            "\x1b[31m[BLOCKED]\x1b[0m"
        },
        chain_str
    );

    let label_snapshot = if let Some(p) = matched_pattern {
        let mut labels = chain.clone();
        if !p.description.is_empty() {
            labels.push(format!("Rule: {}", p.description));
        }
        labels
    } else {
        chain.clone()
    };

    let _ = state
        .logger
        .log_security_event(crate::logger::SecurityEventParams {
            event_id,
            event: &event,
            comm,
            target: path,
            chain: chain.clone(),
            authorized: is_authorized,
            complete: is_complete,
            label_snapshot,
        });
    let _ = state.event_tx.send(msg);

    let nm = state.notification_manager.clone();
    let ev_type = if is_authorized {
        kprotect_common::EventTypeFilter::Verified
    } else {
        kprotect_common::EventTypeFilter::Blocked
    };
    nm.match_and_dispatch(ev_type, path, serde_json::json!({ "id": event_id, "pid": event.pid, "target": path, "status": status_str, "authorized": is_authorized })).await;

    Ok(())
}

#[inline]
fn should_process_event(event_type: u32, engine_enabled: bool) -> bool {
    // We always process Birth (3) and Exit (4) for lineage tracking,
    // regardless of the engine status. This is the "Smart Suspend" behavior.
    engine_enabled || event_type == 3 || event_type == 4
}

fn bytes_to_string(bytes: &[u8]) -> String {
    let null_pos = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..null_pos]).to_string()
}

fn parse_enriched_args(bytes: &[u8], argc: u32) -> Option<String> {
    if bytes.is_empty() || bytes[0] == 0 {
        return None;
    }

    if argc <= 1 {
        return Some("<no_params>".to_string());
    }

    // raw block contains argv[0]\0argv[1]\0argv[2]\0...
    let mut parts = bytes.split(|&b| b == 0);

    // Skip argv[0]
    parts.next()?;

    // Collect the rest up to argc-1 parts
    let args: Vec<String> = parts
        .take((argc - 1) as usize)
        .map(|p| String::from_utf8_lossy(p).trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    if args.is_empty() {
        Some("<no_params>".to_string())
    } else {
        Some(args.join(" "))
    }
}
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_should_process_event_engine_enabled() {
        // If engine is enabled, all events (1-4) should be processed
        assert!(should_process_event(1, true)); // Verified
        assert!(should_process_event(2, true)); // Blocked
        assert!(should_process_event(3, true)); // Birth
        assert!(should_process_event(4, true)); // Exit
    }

    #[test]
    fn test_should_process_event_engine_disabled_smart_suspend() {
        // If engine is disabled, only Birth (3) and Exit (4) should be processed
        assert!(!should_process_event(1, false)); // Verified -> Skip
        assert!(!should_process_event(2, false)); // Blocked -> Skip
        assert!(should_process_event(3, false)); // Birth -> Process (Lineage)
        assert!(should_process_event(4, false)); // Exit -> Process (Lineage)
    }

    #[test]
    fn test_parse_enriched_args() {
        // Block contains argv[0]\0argv[1]\0argv[2]\0...
        let raw = b"ls\0-l\0-a\0/etc\0";
        let res = parse_enriched_args(raw, 4);
        assert_eq!(res.unwrap(), "-l -a /etc");

        // Single arg (no params)
        let raw2 = b"ls\0";
        let res2 = parse_enriched_args(raw2, 1);
        assert_eq!(res2.unwrap(), "<no_params>");

        // Empty block
        let res3 = parse_enriched_args(b"", 0);
        assert!(res3.is_none());
    }

    #[test]
    fn test_evaluate_security_logic() {
        let mut exact_cache = std::collections::HashMap::new();
        let suffix_cache = crate::core::domain::ChainTrieNode::new();
        let chain = vec!["/bin/bash".into()];

        // Case 1: Disabled -> Authorized(None)
        let v1 = evaluate_security_logic(&chain, false, &exact_cache, &suffix_cache);
        assert!(matches!(v1, SecurityVerdict::Authorized(None)));

        // Case 2: Enabled, Empty Cache -> Blocked
        let v2 = evaluate_security_logic(&chain, true, &exact_cache, &suffix_cache);
        assert!(matches!(v2, SecurityVerdict::Blocked));

        // Case 3: Enabled, Matched -> Authorized(Some)
        exact_cache.insert(
            chain.clone(),
            kprotect_common::AuthorizedPattern {
                pattern: chain.clone(),
                match_mode: kprotect_common::MatchMode::Exact,
                description: "bash".into(),
                authorized_at: 0,
            },
        );
        let v3 = evaluate_security_logic(&chain, true, &exact_cache, &suffix_cache);
        match v3 {
            SecurityVerdict::Authorized(Some(p)) => assert_eq!(p.description, "bash"),
            _ => panic!("Should be authorized"),
        }
    }
}
