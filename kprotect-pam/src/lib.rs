// use chrono; - Redundant import, used via chrono::... below
use pam_sys::{PamHandle, PamReturnCode};
use std::io::{BufRead, BufReader, Write};
use std::os::raw::{c_char, c_int};
use std::os::unix::net::UnixStream;
use std::time::Duration;

const SOCKET_PATH: &str = "/run/kprotect/kprotect.sock";
const TIMEOUT_MS: u64 = 100;

fn log_diagnostic(msg: &str) {
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open("/tmp/kprotect_pam.log")
    {
        let now = chrono::Local::now();
        let _ = writeln!(f, "[{}] {}", now.format("%Y-%m-%d %H:%M:%S"), msg);
    }
}

fn resolve_path(cmd: &str) -> String {
    if cmd.contains('/') {
        if let Ok(path) = std::fs::canonicalize(cmd) {
            return path.to_string_lossy().into_owned();
        }
        return cmd.to_string();
    }

    if let Ok(paths) = std::env::var("PATH") {
        for path in paths.split(':') {
            let p = std::path::Path::new(path).join(cmd);
            if p.exists() {
                if let Ok(abs_path) = std::fs::canonicalize(p) {
                    return abs_path.to_string_lossy().into_owned();
                }
            }
        }
    }

    cmd.to_string()
}

fn get_sudo_target_command() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 {
        return None;
    }

    let mut skip_next = false;
    for arg in args.iter().skip(1) {
        // Skip argv[0] (sudo)
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            let idx = args.iter().position(|r| r == "--").unwrap();
            if idx + 1 < args.len() {
                return Some(resolve_path(&args[idx + 1]));
            }
            return None;
        }

        if arg.starts_with("-") {
            // -u user, -g group, -C fd, -p prompt, -r role, -t type, -U other_user
            if ["-u", "-g", "-C", "-p", "-r", "-t", "-U"].contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }

        // Found first non-flag argument -> This is the command
        return Some(resolve_path(arg));
    }
    None
}

/// # Safety
///
/// This function is called by the PAM library. The caller must ensure that `pamh` is a valid
/// pointer to a `PamHandle`, and that `argv` is a valid pointer to an array of `argc` valid
/// null-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // Legacy support: We now enforce in acct_mgmt, but keep this for standard auth too
    perform_kprotect_check(pamh, flags, argc, argv)
}

/// # Safety
///
/// This function is called by the PAM library. The caller must ensure that `_pamh` is a valid
/// pointer to a `PamHandle`, and that `_argv` is a valid pointer to an array of `_argc` valid
/// null-terminated strings (even though they are currently unused).
#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PamReturnCode::SUCCESS as c_int
}

/// # Safety
///
/// This function is called by the PAM library. The caller must ensure that `pamh` is a valid
/// pointer to a `PamHandle`, and that `argv` is a valid pointer to an array of `argc` valid
/// null-terminated strings.
#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    pamh: *mut PamHandle,
    flags: c_int,
    argc: c_int,
    argv: *const *const c_char,
) -> c_int {
    // CRITICAL: Sudo always calls acct_mgmt even if it bypasses authenticate due to caching.
    // This ensures kprotect ALWAYS checks the lineage, regardless of sudo's internal cache.
    perform_kprotect_check(pamh, flags, argc, argv)
}

fn perform_kprotect_check(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    // 1. Get our own PID (the process requesting sudo)
    let pid = std::process::id();

    log_diagnostic(&format!("PAM check for PID {}", pid));

    // 2. Connect to kprotect daemon
    let mut stream = match UnixStream::connect(SOCKET_PATH) {
        Ok(s) => s,
        Err(e) => {
            log_diagnostic(&format!("❌ Connection failed: {}", e));
            // FAIL-OPEN: If daemon is down, don't lock user out of sudo
            // (Standard security compromise - adjust if true airgap is needed)
            return PamReturnCode::SUCCESS as c_int;
        }
    };

    // 3. Set strict timeouts
    let timeout = Duration::from_millis(TIMEOUT_MS);
    let _ = stream.set_read_timeout(Some(timeout));
    let _ = stream.set_write_timeout(Some(timeout));

    // 4. Send CHECK_SUDO command with optional target command
    let target_cmd = get_sudo_target_command();
    let cmd = if let Some(target) = target_cmd {
        format!("CHECK_SUDO {} {}\n", pid, target)
    } else {
        format!("CHECK_SUDO {}\n", pid)
    };

    if stream.write_all(cmd.as_bytes()).is_err() {
        log_diagnostic("❌ Failed to write to socket");
        return PamReturnCode::AUTH_ERR as c_int;
    }

    // 5. Read response
    let mut reader = BufReader::new(stream);
    let mut response = String::new();
    if reader.read_line(&mut response).is_err() {
        log_diagnostic("❌ Failed to read from socket");
        return PamReturnCode::AUTH_ERR as c_int;
    }

    log_diagnostic(&format!("   Daemon response: {}", response.trim()));

    // 6. Evaluate response
    if response.starts_with("OK") {
        log_diagnostic("   Verdict: SUCCESS");
        return PamReturnCode::SUCCESS as c_int;
    }

    if response.starts_with("IGNORE") {
        log_diagnostic("   Verdict: IGNORE");
        return PamReturnCode::IGNORE as c_int;
    }

    // If it's explicitly DENY or anything else available, we block.
    log_diagnostic("   Verdict: AUTH_ERR");
    PamReturnCode::AUTH_ERR as c_int
}
