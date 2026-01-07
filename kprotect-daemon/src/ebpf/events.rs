use anyhow::{Result, Context};
use std::sync::Arc;
use tokio::sync::Mutex;
use aya::maps::{Map, MapData, HashMap as BpfHashMap};
use aya::maps::perf::AsyncPerfEventArray;
use aya::util::online_cpus;
use bytes::BytesMut;
use log::{info, error, warn};

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

use crate::state::AppState;
use crate::core::domain::LineageNode;
use crate::core::process::{build_lineage_chain, cleanup_parent_chain};
use crate::core::auth::is_chain_authorized;

pub async fn monitor_ebpf_events(map: Map, state: Arc<Mutex<AppState>>, auth_map: Arc<Mutex<BpfHashMap<MapData, u64, u8>>>, sig_map: Arc<Mutex<BpfHashMap<MapData, u32, u64>>>) -> Result<()> {
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
            let mut buffers = (0..256).map(|_| BytesMut::with_capacity(4096)).collect::<Vec<_>>();
            while let Ok(events) = buf.read_events(&mut buffers).await {
                for i in 0..events.read {
                    let event = unsafe { std::ptr::read_unaligned(buffers[i].as_ptr() as *const BridgeEvent) };
                    let _ = process_event(event, &state_clone, &auth_map_clone, &sig_map_clone).await;
                }
            }
        });
    }

    // Keep task alive
    std::future::pending::<()>().await;
    Ok(())
}

async fn process_event(event: BridgeEvent, state: &Arc<Mutex<AppState>>, auth_map: &Arc<Mutex<BpfHashMap<MapData, u64, u8>>>, sig_map: &Arc<Mutex<BpfHashMap<MapData, u32, u64>>>) -> Result<()> {
    let comm = bytes_to_string(&event.comm);
    let path = bytes_to_string(&event.path);
    
    // Type of event (1: Verified, 3: Birth, 4: Exit)
    if event.event_type == 3 {
        let enriched_arg = parse_enriched_args(&event.arg, event.argc);
        
        // BIRTH logging disabled for production (can be re-enabled for debugging)
        // println!("BIRTH pid={} ppid={} signature: 0x{:x} path={}", 
        //          event.pid, event.ppid, event.signature, path);
        
        let mut state_lock = state.lock().await;
        
        // PID REUSE DETECTION: If PID exists but start_time is different, clean up the old process first
        if let Some(old_node) = state_lock.lineage_cache.get(&event.pid) {
            if old_node.start_time != event.start_time {
                let old_ppid = old_node.ppid;
                state_lock.lineage_cache.remove(&event.pid);
                cleanup_parent_chain(&mut state_lock.lineage_cache, old_ppid);
            }
        }

        // Insert new process with reference counting fields
        state_lock.lineage_cache.insert(event.pid, LineageNode {
            path: if path.is_empty() { comm.clone() } else { path.clone() },
            arg: enriched_arg,
            ppid: event.ppid,
            start_time: event.start_time,
            signature: event.signature, // Use kernel provided signature!
            child_count: 0,
            is_exited: false,
        });
        
        // Increment parent's child count
        if let Some(parent) = state_lock.lineage_cache.get_mut(&event.ppid) {
            parent.child_count += 1;
        }
        
        // =================================================================================
        // GOVERNOR LOGIC: Check if this new process matches any authorized pattern
        // =================================================================================
        
        // 1. Build the chain for this new process
        let (chain, _) = build_lineage_chain(event.pid, &comm, &path, &state_lock.lineage_cache);
        
        // 2. Check against authorized patterns
        if is_chain_authorized(&chain, &state_lock.auth_exact_cache, &state_lock.auth_suffix_cache) {
            info!("🛡️ Governor: Authorized PID {} ({}) due to pattern match!", event.pid, chain.join(" -> "));
            
            // 3. Update the Kernel Map (Allowlist)
            let mut auth_map_lock = auth_map.lock().await;
            if let Err(e) = auth_map_lock.insert(event.signature, 1, 0) {
                error!("❌ Failed to update Kernel Map for PID {}: {}", event.pid, e);
            } else {
                info!("✅ Kernel Map updated for signature 0x{:x}", event.signature);
            }
        } else {
            // debug!("Governor: PID {} does not match any pattern", event.pid);
        }
        
        return Ok(());
    }
    
    // Handle EXIT events (event_type == 4)
    if event.event_type == 4 {
        let mut state_lock = state.lock().await;
        
        // Mark process as exited - ONLY if start_time matches
        if let Some(node) = state_lock.lineage_cache.get_mut(&event.pid) {
            if node.start_time == event.start_time {
                node.is_exited = true;
                
                // If no children, remove immediately and cascade up
                if node.child_count == 0 {
                    let ppid = node.ppid;
                    state_lock.lineage_cache.remove(&event.pid);
                    
                    // Cascade cleanup: decrement parent's child_count
                    cleanup_parent_chain(&mut state_lock.lineage_cache, ppid);
                }
            } else {
                // debug!("Ignored EXIT for PID {} due to start_time mismatch (old process)", event.pid);
            }
        }
        
        return Ok(());
    }

    let _status = if event.event_type == 1 { 
        "\x1b[32mVERIFIED\x1b[0m" 
    } else { 
        "\x1b[31mBLOCK\x1b[0m" 
    };
    
    let _sig_hex = format!("0x{:x}", event.signature);
    
    // Reconstruct chain
    let (chain, is_complete) = {
        let state_lock = state.lock().await;
        build_lineage_chain(event.pid, &comm, &path, &state_lock.lineage_cache)
    };
    
    // Completeness tracking removed - pattern-based auth doesn't need it

    let chain_str = chain.join(" -> ");
    
    let is_authorized = {
        let state_lock = state.lock().await;
        is_chain_authorized(&chain, &state_lock.auth_exact_cache, &state_lock.auth_suffix_cache)
    };
    
    // Broadcast event with authorization status
    let status_str = if is_authorized {
        "Verified"
    } else {
        "Blocked"
    };

    let prefix = if status_str == "Verified" { "\x1b[32m[AUTHORIZED]\x1b[0m" } else if is_complete { "\x1b[36m[SYSTEM]\x1b[0m" } else { "\x1b[33m[...]\x1b[0m" };

    let pid = event.pid;
    let comm = std::str::from_utf8(&event.comm)
        .unwrap_or("<invalid>")
        .trim_end_matches('\0');
    let sig_hex = format!("0x{:x}", event.signature);

    // Increment event sequence and stats
    let (event_id, current_key) = {
        let mut state_lock = state.lock().await;
        state_lock.event_sequence += 1;
        
        if is_authorized {
            state_lock.events_verified += 1;
        } else {
            state_lock.events_blocked += 1;
        }
        
        (state_lock.event_sequence, state_lock.encryption_key.clone())
    };

    // We no longer save state on every event to prevent disk I/O bottlenecks.
    // The event sequence will be recovered from logs on startup.

    let timestamp = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();

    let msg = serde_json::json!({
        "id": event_id,
        "timestamp": timestamp,
        "pid": pid,
        "signature": sig_hex,
        "status": status_str,
        "comm": comm,
        "chain": chain,
        "chain_str": chain_str,
        "target": path,
        "authorized": is_authorized,
        "complete": is_complete
    }).to_string();
    
    // Console output for headless systems (skip BIRTH events)
    if status_str != "BIRTH" {
        println!(
            "{:<8} {:<4} {:<12} {:<15} {} -> {}",
            pid, event_id, status_str, comm, prefix, chain_str
        );
    }
    use std::io::Write;
    let _ = std::io::stdout().flush();
    
    let state_lock = state.lock().await;

    // Log the security event (BLOCK or VERIFIED)
    if event.event_type == 1 || event.event_type == 2 {
        if let Err(e) = state_lock.logger.log_security_event(
            event_id,
            &event,
            comm,
            &path, // Use 'path' as 'target'
            chain.clone(),
            is_authorized,
            is_complete
        ) {
            warn!("Failed to log security event: {}", e);
        }
    }

    // Trigger Notifications
    let nm = state_lock.notification_manager.clone();
    let ev_type = if is_authorized {
        kprotect_common::EventTypeFilter::Verified
    } else {
        kprotect_common::EventTypeFilter::Blocked
    };
    let event_json = serde_json::json!({
        "id": event_id,
        "pid": pid,
        "signature": sig_hex,
        "status": status_str,
        "comm": comm,
        "chain": chain,
        "chain_str": chain_str,
        "target": path,
        "authorized": is_authorized,
        "complete": is_complete
    });

    let _ = state_lock.event_tx.send(msg);
    drop(state_lock);

    nm.match_and_dispatch(ev_type, &path, event_json).await;

    Ok(())
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
