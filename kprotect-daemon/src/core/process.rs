use crate::core::domain::LineageNode;
use dashmap::DashMap;

/// Build the process lineage chain from a starting PID
/// Returns (chain of strings, true if reached root/known parent)
pub fn build_lineage_chain(
    pid: u32,
    _comm: &str,
    _path: &str,
    cache: &DashMap<u32, LineageNode>,
) -> (Vec<String>, bool) {
    let mut chain = Vec::new();
    let mut current_pid = pid;
    let mut reached_root = false;

    // Chase PIDs up to 10 levels
    for _i in 0..10 {
        if let Some(node) = cache.get(&current_pid) {
            // Show full path instead of just filename
            let display_name = if let Some(arg) = &node.arg {
                format!("{} [{}]", node.path, arg)
            } else {
                node.path.clone()
            };

            chain.push(display_name);

            if current_pid == 1 {
                reached_root = true;
                break;
            }

            if node.ppid == 0 || node.ppid == current_pid {
                break;
            }
            current_pid = node.ppid;
        } else {
            // Stop if process is not in cache
            if current_pid > 1 {
                chain.push(format!("PID:{}", current_pid));
            } else if current_pid == 1 {
                reached_root = true;
            }
            break;
        }
    }

    chain.reverse();
    (chain, reached_root)
}

/// Recursively clean up parent chain when children exit
/// This prevents memory leaks by removing exited processes with no living children
pub fn cleanup_parent_chain(cache: &DashMap<u32, LineageNode>, mut ppid: u32) {
    loop {
        if ppid == 0 {
            break;
        }

        if let Some(mut parent) = cache.get_mut(&ppid) {
            // Decrement parent's child count
            if parent.child_count > 0 {
                parent.child_count -= 1;
            }

            // If parent has exited and has no more children, remove it
            let (should_cascade, grandparent_id) = if parent.is_exited && parent.child_count == 0 {
                (true, parent.ppid)
            } else {
                (false, 0)
            };

            drop(parent); // Release DashMap RefMut lock before removal

            if should_cascade {
                cache.remove(&ppid);
                ppid = grandparent_id; // Continue cascade
            } else {
                break; // Stop cascade
            }
        } else {
            break; // Parent not in cache
        }
    }
}

/// Periodic cleanup of exited processes from lineage cache
/// This prevents memory leaks by aggressively removing processes marked as exited
/// Can be called with is_forced=true to override child_count checks (for emergency cleanup)
pub fn cleanup_exited_processes(cache: &DashMap<u32, LineageNode>, is_forced: bool) -> usize {
    let mut removed_count = 0;

    // Collect PIDs to remove (avoid holding locks during iteration)
    let pids_to_remove: Vec<u32> = cache
        .iter()
        .filter(|entry| {
            let node = entry.value();
            // Remove if exited with no children, or if forced cleanup
            node.is_exited && (node.child_count == 0 || is_forced)
        })
        .map(|entry| *entry.key())
        .collect();

    // Now remove them
    for pid in pids_to_remove {
        if let Some((_, node)) = cache.remove(&pid) {
            // Cascade cleanup to parent
            cleanup_parent_chain(cache, node.ppid);
            removed_count += 1;
        }
    }

    removed_count
}
