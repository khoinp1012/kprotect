// Helper function to get username from socket peer credentials
fn get_username_from_socket(stream: &std::os::unix::net::UnixStream) -> String {
    use nix::sys::socket::{getsockopt, sockopt::PeerCred};
    use std::os::unix::io::AsRawFd;
    
    match getsockopt(stream.as_raw_fd(), PeerCred) {
        Ok(creds) => {
            let uid = creds.uid();
            
            // Try to get username from UID
            unsafe {
                let pw = libc::getpwuid(uid);
                if !pw.is_null() {
                    let name_cstr = std::ffi::CStr::from_ptr((*pw).pw_name);
                    if let Ok(name_str) = name_cstr.to_str() {
                        return name_str.to_string();
                    }
                }
            }
            
            // Fallback to uid:N
            format!("uid:{}", uid)
        }
        Err(_) => "unknown".to_string(),
    }
}
