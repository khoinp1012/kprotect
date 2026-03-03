#!/bin/bash

# --- Configuration & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# --- Logging Functions ---
info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# --- Root Check ---
if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root. Try: sudo $0"
fi

info "Starting kprotect uninstallation..."

# Stop and disable service
if systemctl is-active --quiet kprotect 2>/dev/null; then
    info "Stopping kprotect service..."
    systemctl stop kprotect
fi

if systemctl is-enabled --quiet kprotect 2>/dev/null; then
    info "Disabling kprotect service..."
    systemctl disable kprotect
fi

# Remove PAM registration
if [ -f "/etc/pam.d/sudo" ]; then
    if grep -q "pam_kprotect.so" /etc/pam.d/sudo; then
        info "Removing kprotect from /etc/pam.d/sudo..."
        sed -i '/pam_kprotect.so/d' /etc/pam.d/sudo
        success "Unregistered Quick Sudo bypass from /etc/pam.d/sudo"
    fi
fi

# Remove binaries
info "Removing binaries..."
rm -f /usr/bin/kprotect-daemon
rm -f /usr/bin/kprotect-cli

# Remove PAM module from system security directories
info "Removing PAM module..."
for dir in "/lib/x86_64-linux-gnu/security" "/usr/lib/security" "/lib/security"; do
    if [ -f "$dir/pam_kprotect.so" ]; then
        rm -f "$dir/pam_kprotect.so"
        success "Removed $dir/pam_kprotect.so"
    fi
done

# Remove service file
if [ -f "/etc/systemd/system/kprotect.service" ]; then
    rm -f "/etc/systemd/system/kprotect.service"
    systemctl daemon-reload
    success "Removed systemd service."
fi

# Optional: Keep configs unless explicitly asked (standard behavior)
warn "Configuration files in /var/lib/kprotect/ remain intact."
warn "Run 'sudo rm -rf /var/lib/kprotect /run/kprotect' to remove all data."

success "kprotect uninstalled successfully."
