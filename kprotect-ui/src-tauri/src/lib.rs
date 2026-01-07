use kprotect_client::KprotectClient;
use tauri::Emitter;
use tokio::io::AsyncBufReadExt;
use tokio::net::UnixStream;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::process::{Child, Command, Stdio};
use std::io::Write;

// Global persistent root worker
// wrapped in simple std Mutex because we only access it from async Tauri commands which run on threads
static ROOT_WORKER: Mutex<Option<Child>> = Mutex::new(None);

// Flag to track if worker has authenticated and is ready
static WORKER_READY: AtomicBool = AtomicBool::new(false);

// Global slot for pending CLI response
static PENDING_RESPONSE: Mutex<Option<String>> = Mutex::new(None);

// Global lock to serialize commands to the worker to prevent race conditions
static COMMAND_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

async fn send_root_command(cmd: &str) -> Result<String, String> {
    // Serialize access - wait for other commands to finish
    let _cmd_guard = COMMAND_LOCK.lock().await;

    // Clear any stale response
    *PENDING_RESPONSE.lock().unwrap() = None;
    
    // Send command to worker (in its own scope to ensure guard is dropped)
    {
        let mut guard = ROOT_WORKER.lock().unwrap();
        if let Some(child) = guard.as_mut() {
            if let Some(stdin) = child.stdin.as_mut() {
                writeln!(stdin, "{}", cmd).map_err(|e| e.to_string())?;
                stdin.flush().map_err(|e| e.to_string())?;
                println!("DEBUG: Sent command to root worker: {}", cmd);
            } else {
                return Err("Worker stdin not available".to_string());
            }
        } else {
            return Err("Root session not active".to_string());
        }
    } // guard is dropped here
    
    // Poll for response with 2-second timeout (20 * 100ms)
    for _ in 0..20 {
        tokio::time::sleep(tokio::time::Duration::from_millis(100)).await;
        
        // Check if response arrived
        if let Some(response) = PENDING_RESPONSE.lock().unwrap().take() {
            return parse_cli_response(&response);
        }
    }
    
    Err("Timeout: CLI worker did not respond within 2 seconds".to_string())
}

fn parse_cli_response(json: &str) -> Result<String, String> {
    // Parse the JSON response from CLI
    let parsed: serde_json::Value = serde_json::from_str(json)
        .map_err(|e| format!("Failed to parse CLI response: {}", e))?;
    
    // Handle array responses (like list_auth which returns the array directly)
    if parsed.is_array() {
        println!("DEBUG [parse_cli_response]: Got array response, returning as-is");
        return Ok(json.to_string());
    }
    
    // Handle object responses with status field
    if let Some(status) = parsed.get("status").and_then(|s| s.as_str()) {
        match status {
            "ok" => Ok("Success".to_string()),
            "error" => {
                let message = parsed.get("message")
                    .and_then(|m| m.as_str())
                    .unwrap_or("Unknown error");
                Err(message.to_string())
            }
            _ => Err(format!("Unknown status: {}", status))
        }
    } else {
        // No status field, return the whole response as string
        println!("DEBUG [parse_cli_response]: No status field, returning full response");
        Ok(json.to_string())
    }
}

// Learn more about Tauri commands at https://tauri.app/develop/calling-rust/
#[tauri::command]
async fn authorize_pattern(pattern: Vec<String>, mode: String, description: Option<String>) -> Result<(), String> {
    // Try root worker first (priority)
    if WORKER_READY.load(Ordering::Relaxed) {
        // Construct command: authorize;pattern;mode;description
        // Pattern is joined by commas
        let pattern_str = pattern.join(",");
        let desc = description.unwrap_or_else(|| "No description".to_string());
        
        let cmd = format!("authorize;{};{};{}", pattern_str, mode, desc);
        
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }

    // Fallback to direct client (will fail if not root/privileged)
    // Note: client library might need update, but focusing on root worker path mainly
    // For now we return error if worker not ready as this new auth system relies on the daemon/worker
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn revoke_pattern(pattern: Vec<String>, match_mode: String) -> Result<(), String> {
    // Try root worker first (priority)
    if WORKER_READY.load(Ordering::Relaxed) {
        let pattern_str = pattern.join(",");
        let cmd = format!("REVOKE_PATTERN;{};{}", pattern_str, match_mode);
        
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }

    // Fallback to direct client
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn get_zones() -> Result<kprotect_client::ZonesConfig, String> {
    eprintln!("DEBUG [get_zones]: Starting get_zones command");
    let client = KprotectClient::new();
    let result = client.list_zones().await.map_err(|e| e.to_string());
    eprintln!("DEBUG [get_zones]: Result: {:?}", result);
    result
}

#[tauri::command]
async fn add_zone(pattern: String) -> Result<(), String> {
    // Try root worker first (priority)
    // Hardcode zone_type to "red" (lowercase) as requested
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("zone_add;red;{}", pattern);
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn remove_zone(pattern: String) -> Result<(), String> {
    // Try root worker first (priority)
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("zone_remove;red;{}", pattern);
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn add_enrichment_pattern(pattern: String) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("pattern_add;{}", pattern);
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn remove_enrichment_pattern(pattern: String) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("pattern_remove;{}", pattern);
        return send_root_command(&cmd)
            .await
            .map(|_| ());
    }
    Err("Root worker not ready. Please trigger root session.".to_string())
}

#[tauri::command]
async fn get_enrichment_patterns() -> Result<kprotect_client::EnrichmentConfig, String> {
    let client = KprotectClient::new();
    client.list_enrichment_patterns().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_capabilities() -> Result<kprotect_client::Capabilities, String> {
    let client = KprotectClient::new();
    client.capabilities().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_daemon_status() -> Result<kprotect_client::DaemonStatus, String> {
    let client = KprotectClient::new();
    client.get_daemon_status().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_encryption_info() -> Result<kprotect_client::EncryptionInfo, String> {
    let client = KprotectClient::new();
    client.get_encryption_info().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_system_info() -> Result<kprotect_client::SystemInfo, String> {
    let client = KprotectClient::new();
    client.get_system_info().await.map_err(|e| e.to_string())
}
#[tauri::command]
async fn get_resource_usage() -> Result<kprotect_common::SystemStats, String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let response = send_root_command("GET_STATS").await?;
        serde_json::from_str(&response).map_err(|e| format!("Failed to parse stats: {}", e))
    } else {
        let client = KprotectClient::new();
        client.get_stats().await.map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn get_log_config() -> Result<kprotect_client::LogConfig, String> {
    let client = KprotectClient::new();
    client.get_log_config().await.map_err(|e| e.to_string())
}

#[tauri::command]
async fn set_log_retention(events: u32, audit: u32) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("set_log_retention;{};{}", events, audit);
        return send_root_command(&cmd).await.map(|_| ());
    }
    Err("Root session required to change settings".to_string())
}

#[tauri::command]
async fn get_security_events(count: usize, offset: usize) -> Result<serde_json::Value, String> {
    let client = KprotectClient::new();
    let events = client.get_events(count, offset).await.map_err(|e| e.to_string())?;
    serde_json::to_value(events).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_audit_logs(count: usize, offset: usize) -> Result<serde_json::Value, String> {
    // Audit logs might contain sensitive info, but since we are in the kprotect group, 
    // the daemon will allow us to read them.
    let client = KprotectClient::new();
    let logs = client.get_audit(count, offset).await.map_err(|e| e.to_string())?;
    serde_json::to_value(logs).map_err(|e| e.to_string())
}

#[tauri::command]
async fn get_notification_rules() -> Result<serde_json::Value, String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let response = send_root_command("notify_list").await?;
        serde_json::from_str(&response).map_err(|e| format!("Failed to parse notification rules: {}", e))
    } else {
        // Fallback to direct client (readonly allowed for kprotect group)
        let client = KprotectClient::new();
        let rules = client.get_notification_rules().await.map_err(|e| e.to_string())?;
        serde_json::to_value(rules).map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn add_notification_rule(
    name: String,
    events: String,
    path: Option<String>,
    action: String,
    dest: String,
    timeout: u32,
) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let path_str = path.unwrap_or_else(|| "null".to_string());
        let cmd = format!("notify_add;{};{};{};{};{};{}", name, events, path_str, action, dest, timeout);
        return send_root_command(&cmd).await.map(|_| ());
    }
    Err("Root session required to manage notifications".to_string())
}

#[tauri::command]
async fn remove_notification_rule(id: u32) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("notify_remove;{}", id);
        return send_root_command(&cmd).await.map(|_| ());
    }
    Err("Root session required to manage notifications".to_string())
}

#[tauri::command]
async fn toggle_notification_rule(id: u32, enabled: bool) -> Result<(), String> {
    if WORKER_READY.load(Ordering::Relaxed) {
        let cmd = format!("notify_toggle;{};{}", id, enabled);
        return send_root_command(&cmd).await.map(|_| ());
    }
    Err("Root session required to manage notifications".to_string())
}

#[tauri::command]
async fn get_patterns() -> Result<serde_json::Value, String> {
    println!("DEBUG [get_patterns]: Starting get_patterns command");
    
    // Try root worker first (priority)
    if WORKER_READY.load(Ordering::Relaxed) {
        println!("DEBUG [get_patterns]: Root worker is ready, sending list_auth command");
        let response = send_root_command("list_auth").await?;
        
        println!("DEBUG [get_patterns]: Received response from root worker: {}", response);
        
        // Parse the JSON response
        match serde_json::from_str(&response) {
            Ok(parsed) => {
                println!("DEBUG [get_patterns]: Successfully parsed JSON, returning to frontend");
                Ok(parsed)
            }
            Err(e) => {
                println!("DEBUG [get_patterns]: Failed to parse JSON: {}", e);
                Err(format!("Failed to parse patterns: {}", e))
            }
        }
    } else {
        println!("DEBUG [get_patterns]: Root worker not ready, falling back to direct client");
        // Fallback to direct client (read-only, works for kprotect group)
        let client = KprotectClient::new();
        let patterns = client.get_patterns().await.map_err(|e| e.to_string())?;
        serde_json::to_value(patterns).map_err(|e| e.to_string())
    }
}

#[tauri::command]
async fn check_root_worker_status() -> Result<bool, String> {
    let mut guard = ROOT_WORKER.lock().unwrap();
    
    if let Some(child) = guard.as_mut() {
        // Check if process is still alive
        match child.try_wait() {
            Ok(Some(_)) => {
                // Process has exited, clear it
                *guard = None;
                WORKER_READY.store(false, Ordering::Relaxed);
                Ok(false)
            }
            Ok(None) => {
                // Process is running - check if it's ready (authenticated)
                Ok(WORKER_READY.load(Ordering::Relaxed))
            }
            Err(e) => Err(format!("Failed to check worker status: {}", e))
        }
    } else {
        Ok(false)
    }
}

#[tauri::command]
async fn stop_root_worker() -> Result<(), String> {
    let mut guard = ROOT_WORKER.lock().unwrap();
    
    if let Some(mut child) = guard.take() {
        // Reset ready flag immediately
        WORKER_READY.store(false, Ordering::Relaxed);
        
        // Try graceful termination first (SIGTERM equivalent via kill())
        match child.kill() {
            Ok(_) => {
                println!("DEBUG: Sent kill signal to root worker");
                
                // Wait for process to exit (with timeout)
                let mut attempts = 0;
                while attempts < 10 {
                    match child.try_wait() {
                        Ok(Some(status)) => {
                            println!("DEBUG: Root worker exited with status: {:?}", status);
                            return Ok(());
                        }
                        Ok(None) => {
                            // Process still running, wait a bit
                            std::thread::sleep(std::time::Duration::from_millis(100));
                            attempts += 1;
                        }
                        Err(e) => {
                            return Err(format!("Failed to check worker status: {}", e));
                        }
                    }
                }
                
                // If we reach here, process didn't exit gracefully
                // Force kill by dropping the Child handle (this triggers SIGKILL on drop)
                drop(child);
                println!("DEBUG: Force-killed root worker after timeout");
                Ok(())
            }
            Err(e) => {
                // If kill() fails, the process might have already exited
                if let Ok(Some(_)) = child.try_wait() {
                    println!("DEBUG: Root worker already exited");
                    Ok(())
                } else {
                    Err(format!("Failed to stop worker: {}", e))
                }
            }
        }
    } else {
        Err("No active root worker to stop".to_string())
    }
}

#[tauri::command]
async fn start_root_session() -> Result<String, String> {
    // "Start Root Session" spawns a persistent background worker running as root.
    // This worker listens for commands via STDIN.
    // This achieves the "Auth Once, Run Many" behavior requested.
    
    let mut guard = ROOT_WORKER.lock().unwrap();
    
    // Reset ready flag before starting new worker
    WORKER_READY.store(false, Ordering::Relaxed);
    
    // Check if alive
    if let Some(child) = guard.as_mut() {
        if let Ok(Some(_)) = child.try_wait() {
            // Child is dead, clear it
            *guard = None;
        } else {
             return Ok("Root session already active.".to_string());
        }
    }
    
    // Determine path to kprotect-cli
    // Try multiple possible locations for better reliability
    
    let current_exe = std::env::current_exe().map_err(|e| e.to_string())?;
    println!("DEBUG: Current executable: {:?}", current_exe);
    
    // Build list of possible CLI locations
    let mut possible_paths = Vec::new();
    
    // Dev mode: workspace/target/debug/kprotect-cli
    // Current exe is at: kprotect-ui/src-tauri/target/debug/kprotect-ui
    // Go up 5 levels to workspace root
    if let Some(workspace) = current_exe
        .parent() // debug/
        .and_then(|p| p.parent()) // target/
        .and_then(|p| p.parent()) // src-tauri/
        .and_then(|p| p.parent()) // kprotect-ui/
        .and_then(|p| p.parent()) // workspace/
    {
        // Check release first (built by dev.sh), then debug
        possible_paths.push(workspace.join("target/release/kprotect-cli"));
        possible_paths.push(workspace.join("target/debug/kprotect-cli"));
    }
    
    // System installation
    possible_paths.push(std::path::PathBuf::from("/usr/local/bin/kprotect-cli"));
    possible_paths.push(std::path::PathBuf::from("/usr/bin/kprotect-cli"));
    
    // Find first existing CLI binary
    let mut cli_path = None;
    for path in &possible_paths {
        println!("DEBUG: Checking CLI path: {:?}", path);
        if path.exists() {
            println!("DEBUG: ✓ Found CLI at: {:?}", path);
            cli_path = Some(path.clone());
            break;
        } else {
            println!("DEBUG: ✗ Not found at: {:?}", path);
        }
    }
    
    let cli_path = cli_path.ok_or_else(|| {
        format!(
            "kprotect-cli binary not found. Searched locations:\n{}",
            possible_paths.iter()
                .map(|p| format!("  - {:?}", p))
                .collect::<Vec<_>>()
                .join("\n")
        )
    })?;
        
    // Debug log to console (visible in terminal where tauri dev is running)
    println!("DEBUG: Using CLI binary: {:?}", cli_path);
        
    let cli_path_str = cli_path.to_str().ok_or("Invalid path")?;

    // Spawn pkexec
    println!("DEBUG: Spawning pkexec with CLI in interactive mode...");
    let mut child = Command::new("pkexec")
        .arg(cli_path_str) // Run our CLI
        .arg("interactive") // In interactive mode
        .stdin(Stdio::piped()) // Capture stdin to write commands
        .stdout(Stdio::piped()) // Capture stdout to detect "ready" message
        .stderr(Stdio::piped()) // Capture stderr to check for errors
        .spawn()
        .map_err(|e| format!("Failed to start root worker (pkexec): {}. Make sure pkexec is installed.", e))?;
    
    // Take stdout to read the "ready" message
    if let Some(stdout) = child.stdout.take() {
        // Spawn background task to wait for ready message
        tauri::async_runtime::spawn(async move {
            use tokio::io::BufReader;
            let mut reader = BufReader::new(tokio::process::ChildStdout::from_std(stdout).unwrap());
            let mut line = String::new();
            
            // Continuously read lines from worker
            loop {
                line.clear();
                println!("DEBUG: Attempting to read line from worker stdout...");
                match reader.read_line(&mut line).await {
                    Ok(0) => {
                        // EOF - worker stopped
                        println!("DEBUG: Worker stdout closed (EOF received)");
                        WORKER_READY.store(false, Ordering::Relaxed);
                        break;
                    }
                    Ok(_) => {
                        let trimmed = line.trim();
                        println!("DEBUG: Worker output: {}", trimmed);
                        
                        // Check for ready message
                        if trimmed.contains("\"status\": \"ready\"") {
                            println!("DEBUG: Worker is ready!");
                            WORKER_READY.store(true, Ordering::Relaxed);
                        }
                        // Check for JSON response (Array or Object)
                        else if (trimmed.starts_with('[') && trimmed.ends_with(']')) || (trimmed.starts_with('{') && trimmed.ends_with('}')) {
                            // Skip the initial "ready" message which we already handled
                            if !trimmed.contains("\"status\": \"ready\"") {
                                println!("DEBUG: Storing response in slot (JSON)");
                                *PENDING_RESPONSE.lock().unwrap() = Some(trimmed.to_string());
                            }
                        }
                        // Else: just a log message, already printed above
                    }
                    Err(e) => {
                        println!("DEBUG: Failed to read from worker stdout: {}", e);
                        break;
                    }
                }
            }
        });
    }
    
    // Store the worker immediately (stdout was taken above)
    *guard = Some(child);
    println!("DEBUG: pkexec spawned, waiting for worker ready message...");
    
    Ok("Root worker spawned. Complete authentication when prompted.".to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_notification::init())
        .invoke_handler(tauri::generate_handler![
            authorize_pattern, 
            revoke_pattern,
            get_patterns,
            get_zones,
            add_zone,
            remove_zone,
            add_enrichment_pattern,
            remove_enrichment_pattern,
            get_enrichment_patterns,
            get_capabilities,
            get_daemon_status,
            get_encryption_info,
            get_system_info,
            get_log_config,
            set_log_retention,
            get_audit_logs,
            get_security_events,
            check_root_worker_status,
            stop_root_worker,
            start_root_session,
            get_notification_rules,
            add_notification_rule,
            remove_notification_rule,
            toggle_notification_rule,
            get_resource_usage
        ])
        .setup(|app| {
            let app_handle = app.handle().clone();
            
            // Spawn background event listener
            tauri::async_runtime::spawn(async move {
                loop {
                    let client = KprotectClient::new();
                    match UnixStream::connect("/run/kprotect/kprotect.sock").await {
                        Ok(mut stream) => {
                            // First, subscribe to live events
                            if let Err(e) = client.subscribe(&mut stream).await {
                                eprintln!("Failed to subscribe to events: {}", e);
                                continue;
                            }
                            
                            let mut reader = tokio::io::BufReader::new(stream);
                            let mut line = String::new();
                            
                            loop {
                                line.clear();
                                match reader.read_line(&mut line).await {
                                    Ok(0) => break, // Connection closed
                                    Ok(_) => {
                                        // Parse JSON to ensure validity, then emit raw string or parsed obj
                                        if let Ok(json) = serde_json::from_str::<serde_json::Value>(&line) {
                                            // Emit event to frontend
                                            println!("DEBUG: Emitting event to frontend: {}", line.trim());
                                            let _ = app_handle.emit("event", json.clone());
                                            
                                            // NOTE: Notifications are now controlled by the frontend toggle system
                                            // The hardcoded backend notification has been removed to respect user preferences
                                        }
                                    }
                                    Err(_) => break,
                                }
                            }
                        }
                        Err(e) => {
                            eprintln!("Failed to connect to daemon: {}", e);
                        }
                    }
                    // Retry delay
                    tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
                }
            });
            
            Ok(())
        })
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
