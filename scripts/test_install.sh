#!/bin/bash
set -e

# --- Configuration & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Logging Functions (Reused from install.sh) ---
info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Resolve project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Resolve project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# --- Build Phase (No root needed) ---
info "Building kprotect in debug mode for testing..."

# Locate cargo reliably
CARGO_CMD="cargo"
if ! command -v cargo &> /dev/null; then
    if [[ -n "$SUDO_USER" ]] && [ -f "/home/$SUDO_USER/.cargo/bin/cargo" ]; then
        CARGO_CMD="/home/$SUDO_USER/.cargo/bin/cargo"
    elif [ -f "$HOME/.cargo/bin/cargo" ]; then
        CARGO_CMD="$HOME/.cargo/bin/cargo"
    else
        error "cargo command not found. Please ensure Rust is installed."
    fi
fi

# If we are running as root via sudo, run cargo as the original user
if [[ $EUID -eq 0 ]] && [[ -n "$SUDO_USER" ]]; then
    info "Running build as $SUDO_USER to preserve Rust environment..."
    # Use -i to source the user's shell profile which usually sets up rustup
    sudo -u "$SUDO_USER" -i bash -c "cd $PROJECT_ROOT && $CARGO_CMD build"
else
    $CARGO_CMD build
fi

# --- Installation Phase (Root needed) ---
info "Installing debug binaries..."

# Helper for conditional sudo
run_as_root() {
    if [[ $EUID -ne 0 ]]; then
        sudo "$@"
    else
        "$@"
    fi
}

run_as_root install -m 755 target/debug/kprotect /usr/bin/kprotect-daemon
success "Installed kprotect-daemon (debug)."

if [ -f "target/debug/kprotect-cli" ]; then
    run_as_root install -m 755 target/debug/kprotect-cli /usr/bin/kprotect-cli
    success "Installed kprotect-cli (debug)."
fi

# Install PAM module
if [ -f "target/debug/libkprotect_pam.so" ]; then
    # Detect PAM directory and install to all common locations to be safe
    info "Installing PAM module to system security directories..."
    for dir in "/lib/x86_64-linux-gnu/security" "/usr/lib/security" "/lib/security"; do
        if [ -d "$dir" ]; then
            run_as_root install -m 644 target/debug/libkprotect_pam.so "$dir/pam_kprotect.so"
            success "Installed to $dir/pam_kprotect.so"
        fi
    done
fi

# Reuse directory creation and service installation logic
info "Configuring environment..."
run_as_root mkdir -p /var/lib/kprotect/configs /run/kprotect
run_as_root chmod 700 /var/lib/kprotect/configs
run_as_root chmod 755 /run/kprotect

info "Installing systemd service..."
if [ -f "scripts/kprotect.service" ]; then
    run_as_root install -m 644 scripts/kprotect.service /etc/systemd/system/
    run_as_root systemctl daemon-reload
    run_as_root systemctl restart kprotect
    success "kprotect service restarted with debug binaries."
else
    error "scripts/kprotect.service not found."
fi

success "Test installation complete! You can now monitor logs with: journalctl -u kprotect -f"
