use kprotect_daemon::server::api::handle_client;
use kprotect_daemon::state::AppState;
use tempfile::tempdir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{UnixListener, UnixStream};

#[tokio::test]
async fn test_api_integration_full_flow() {
    // 1. Setup temporary directory for socket and configs
    let dir = tempdir().unwrap();
    let socket_path = dir.path().join("test.sock");

    // 2. Setup Mock AppState
    let state = AppState::mock_test();

    // 3. Start API Listener in background
    let listener = UnixListener::bind(&socket_path).unwrap();
    let state_clone = state.clone();

    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            let s_clone = state_clone.clone();
            tokio::spawn(async move {
                let _ = handle_client(stream, s_clone).await;
            });
        }
    });

    // 4. Test PING
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    client.write_all(b"PING\n").await.unwrap();
    let mut buf = [0u8; 128];
    let n = client.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("OK: PONG"));

    // 5. Test VERSION
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    client.write_all(b"VERSION\n").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    assert!(String::from_utf8_lossy(&buf[..n]).contains("v0.1.0"));

    // 6. Test SET_ENGINE (Toggle logic)
    // Initially enabled (default)
    {
        let rules = state.rules.read().unwrap();
        assert!(rules.config.engine_enabled);
    }

    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    // Assuming root for this test as mock_test uses default UID checks in handle_client
    // Wait, handle_client uses stream.peer_cred() which will be the test runners UID.
    // If the test runner is not root, SET_ENGINE might fail.
    // Let's check handle_set_engine's permission check.

    client.write_all(b"SET_ENGINE;false\n").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    // If we are not root, we expect a permission error.
    // If we are root, we expect OK.
    if resp.contains("OK") {
        let rules = state.rules.read().unwrap();
        assert!(!rules.config.engine_enabled);
    } else {
        assert!(resp.contains("PERMISSION"));
    }

    // 7. Test AUTHORIZE (Chain authorization)
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    client
        .write_all(b"AUTHORIZE;bash,ls;Exact;Test Pattern\n")
        .await
        .unwrap();
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);

    if resp.contains("OK") {
        let rules = state.rules.read().unwrap();
        assert_eq!(rules.authorized_patterns.len(), 1);
        assert_eq!(rules.authorized_patterns[0].pattern, vec!["bash", "ls"]);
    } else {
        assert!(resp.contains("PERMISSION"));
    }

    // 8. Test STATS
    let mut client = UnixStream::connect(&socket_path).await.unwrap();
    client.write_all(b"STATS\n").await.unwrap();
    let n = client.read(&mut buf).await.unwrap();
    let resp = String::from_utf8_lossy(&buf[..n]);
    assert!(resp.contains("OK: {"));
    assert!(resp.contains("\"ebpf_loaded\":true"));
}
