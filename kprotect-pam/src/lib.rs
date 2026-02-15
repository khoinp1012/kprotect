use pam_sys::{PamHandle, PamReturnCode};
use std::os::raw::{c_char, c_int};
use std::io::{Write, BufReader, BufRead};
use std::os::unix::net::UnixStream;
use std::time::Duration;
use chrono;

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

fn get_sudo_target_command() -> Option<String> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 2 { return None; }

    let mut skip_next = false;
    for arg in args.iter().skip(1) { // Skip argv[0] (sudo)
        if skip_next {
            skip_next = false;
            continue;
        }

        if arg == "--" {
            // Found separator, next arg is command
            // We need to return the one *after* this in the iteration, but iter doesn't peek.
            // Simplified: we just stop treating things as flags. 
            // Better logic: find index and take next.
            let idx = args.iter().position(|r| r == "--").unwrap();
            if idx + 1 < args.len() {
                return Some(args[idx + 1].clone());
            }
            return None;
        }

        if arg.starts_with("-") {
            // Flags that take an argument
            // -u user, -g group, -C fd, -p prompt, -r role, -t type, -U other_user
            if ["-u", "-g", "-C", "-p", "-r", "-t", "-U"].contains(&arg.as_str()) {
                skip_next = true;
            }
            continue;
        }

        // Found first non-flag argument -> This is the command
        // EXCEPTION: "sudo -s" or "sudo -i" runs a shell.
        return Some(arg.clone());
    }
    None
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_authenticate(
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
            return PamReturnCode::AUTH_ERR as c_int;
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
        return PamReturnCode::SUCCESS as c_int;
    }

    PamReturnCode::AUTH_ERR as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_setcred(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PamReturnCode::SUCCESS as c_int
}

#[no_mangle]
pub unsafe extern "C" fn pam_sm_acct_mgmt(
    _pamh: *mut PamHandle,
    _flags: c_int,
    _argc: c_int,
    _argv: *const *const c_char,
) -> c_int {
    PamReturnCode::IGNORE as c_int
}
