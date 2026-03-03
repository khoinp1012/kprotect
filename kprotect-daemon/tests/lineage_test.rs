use dashmap::DashMap;
use kprotect_daemon::core::domain::LineageNode;
use kprotect_daemon::core::process::{build_lineage_chain, cleanup_parent_chain};
use std::sync::Arc;
use tokio::time::{sleep, Duration};

#[tokio::test]
async fn test_lineage_chain_building() {
    let cache = DashMap::new();

    // Simulate systemd (PID 1)
    cache.insert(
        1,
        LineageNode {
            path: "/usr/lib/systemd/systemd".to_string(),
            arg: None,
            ppid: 0,
            start_time: 1000,
            signature: 0x1,
            child_count: 1,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    // Simulate sshd (PID 100, parent 1)
    cache.insert(
        100,
        LineageNode {
            path: "/usr/sbin/sshd".to_string(),
            arg: None,
            ppid: 1,
            start_time: 2000,
            signature: 0x2,
            child_count: 1,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    // Simulate bash (PID 200, parent 100)
    cache.insert(
        200,
        LineageNode {
            path: "/bin/bash".to_string(),
            arg: Some("-bash".to_string()),
            ppid: 100,
            start_time: 3000,
            signature: 0x3,
            child_count: 0,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    let (chain, complete) = build_lineage_chain(200, "bash", "/bin/bash", &cache);

    assert_eq!(chain.len(), 3);
    assert_eq!(chain[0], "/usr/lib/systemd/systemd");
    assert_eq!(chain[1], "/usr/sbin/sshd");
    assert_eq!(chain[2], "/bin/bash [-bash]");
    assert!(complete);
}

#[tokio::test]
async fn test_incomplete_lineage_chain() {
    let cache = DashMap::new();

    // PID 200: bash
    // Parent PID 100 is NOT in cache
    cache.insert(
        200,
        LineageNode {
            path: "/bin/bash".to_string(),
            arg: None,
            ppid: 100,
            start_time: 3000,
            signature: 0x3,
            child_count: 0,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    let (chain, complete) = build_lineage_chain(200, "bash", "/bin/bash", &cache);

    // Should contain PID:100 and the current proc
    assert_eq!(chain.len(), 2);
    assert_eq!(chain[0], "PID:100");
    assert_eq!(chain[1], "/bin/bash");
    assert!(!complete);
}

#[tokio::test]
async fn test_pid_reuse_healing() {
    let cache = DashMap::new();

    // PID 500: First instance
    cache.insert(
        500,
        LineageNode {
            path: "/usr/bin/old_proc".to_string(),
            arg: None,
            ppid: 1,
            start_time: 5000,
            signature: 0xA,
            child_count: 0,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    // Simulate PID 1 having 1 child
    cache.insert(
        1,
        LineageNode {
            path: "systemd".to_string(),
            arg: None,
            ppid: 0,
            start_time: 1000,
            signature: 0x1,
            child_count: 1,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    let new_start_time = 6000;

    // Logic from events.rs
    if let Some(old_node) = cache.get(&500) {
        if old_node.start_time != new_start_time {
            let old_ppid = old_node.ppid;
            drop(old_node);
            cache.remove(&500);
            cleanup_parent_chain(&cache, old_ppid);
        }
    }

    // Verification: Parent child count should be 0 now
    let parent = cache.get(&1).unwrap();
    assert_eq!(parent.child_count, 0);
    assert!(cache.get(&500).is_none());
}

#[tokio::test]
async fn test_recursive_cleanup() {
    let cache = DashMap::new();

    // Chain: 1 -> 10 -> 20
    cache.insert(
        1,
        LineageNode {
            path: "1".into(),
            arg: None,
            ppid: 0,
            start_time: 1,
            signature: 1,
            child_count: 1,
            is_exited: false,
            sudo_ancestor: None,
        },
    );
    cache.insert(
        10,
        LineageNode {
            path: "10".into(),
            arg: None,
            ppid: 1,
            start_time: 10,
            signature: 10,
            child_count: 1,
            is_exited: true,
            sudo_ancestor: None,
        },
    );
    cache.insert(
        20,
        LineageNode {
            path: "20".into(),
            arg: None,
            ppid: 10,
            start_time: 20,
            signature: 20,
            child_count: 0,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    // Now 20 exits
    if let Some(mut node_20) = cache.get_mut(&20) {
        node_20.is_exited = true;
    }

    let ppid = {
        let node_20 = cache.get(&20).unwrap();
        node_20.ppid
    };

    cache.remove(&20);
    cleanup_parent_chain(&cache, ppid);

    // 10 was already exited and now has 0 children -> should be gone
    assert!(cache.get(&20).is_none());
    assert!(cache.get(&10).is_none());

    // 1 is not exited -> should remain but child_count should be 0
    let node_1 = cache.get(&1).unwrap();
    assert_eq!(node_1.child_count, 0);
}

#[tokio::test]
async fn test_concurrency_stress() {
    let cache = Arc::new(DashMap::new());

    // Simulate parent always present
    cache.insert(
        1,
        LineageNode {
            path: "parent".into(),
            arg: None,
            ppid: 0,
            start_time: 1,
            signature: 1,
            child_count: 0,
            is_exited: false,
            sudo_ancestor: None,
        },
    );

    let mut tasks = Vec::new();
    for i in 1..101 {
        let cache_task = cache.clone();
        tasks.push(tokio::spawn(async move {
            let pid = i as u32 + 1000;
            cache_task.insert(
                pid,
                LineageNode {
                    path: format!("proc_{}", i),
                    arg: None,
                    ppid: 1,
                    start_time: i as u64,
                    signature: i as u64,
                    child_count: 0,
                    is_exited: false,
                    sudo_ancestor: None,
                },
            );

            // Increment parent
            if let Some(mut parent) = cache_task.get_mut(&1) {
                parent.child_count += 1;
            }

            sleep(Duration::from_millis(5)).await;

            // Exit and cleanup
            if let Some(mut node) = cache_task.get_mut(&pid) {
                node.is_exited = true;
            }
            cache_task.remove(&pid);
            cleanup_parent_chain(&cache_task, 1);
        }));
    }

    for t in tasks {
        t.await.unwrap();
    }

    // Cache should only contain the parent, and child_count should be zero
    assert_eq!(cache.len(), 1);
    let parent = cache.get(&1).unwrap();
    assert_eq!(parent.child_count, 0);
}
