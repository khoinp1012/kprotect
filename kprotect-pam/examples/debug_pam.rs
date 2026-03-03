use pam_sys::{PamHandle, PamReturnCode};

fn main() {
    let _pamh: *mut PamHandle = std::ptr::null_mut();
    let _ = PamReturnCode::SUCCESS;
    let _ = PamReturnCode::AUTH_ERR;
    let _ = PamReturnCode::IGNORE;
}
