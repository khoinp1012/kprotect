use std::collections::HashMap;
use crate::core::domain::LineageNode;

/// Build the process lineage chain from a starting PID
/// Returns (chain of strings, true if reached root/known parent)
pub fn build_lineage_chain(pid: u32, comm: &str, _path: &str, cache: &HashMap<u32, LineageNode>) -> (Vec<String>, bool) {
    let mut chain = Vec::new();
    let mut current_pid = pid;
    let mut reached_root = false;
    
    // Don't add comm here - the process will be added from cache with full path
    // This prevents duplicate entries like "/usr/bin/cat → cat"
    
    // Chase PIDs up to 10 levels
    for i in 0..10 {
        if current_pid <= 1 {
            reached_root = true;
            break;
        }

        if let Some(node) = cache.get(&current_pid) {
            // Show full path instead of just filename
            let display_name = if let Some(arg) = &node.arg {
                format!("{} [{}]", node.path, arg)
            } else {
                node.path.clone()
            };
            
            chain.push(display_name);

            if node.ppid == 0 || node.ppid == current_pid { 
                break; 
            }
            current_pid = node.ppid;
        } else {
            // Stop if process is not in cache
            break;
        }
    }
    
    chain.reverse();
    (chain, reached_root)
}

/// Recursively clean up parent chain when children exit
/// This prevents memory leaks by removing exited processes with no living children
pub fn cleanup_parent_chain(cache: &mut HashMap<u32, LineageNode>, mut ppid: u32) {
    loop {
        if ppid == 0 {
            break;
        }
        
        if let Some(parent) = cache.get_mut(&ppid) {
            // Decrement parent's child count
            if parent.child_count > 0 {
                parent.child_count -= 1;
            }
            
            // If parent has exited and has no more children, remove it
            if parent.is_exited && parent.child_count == 0 {
                let grandparent_pid = parent.ppid;
                cache.remove(&ppid);
                ppid = grandparent_pid;  // Continue cascade
            } else {
                break;  // Stop cascade
            }
        } else {
            break;  // Parent not in cache
        }
    }
}
