#!/bin/bash
set -e

# --- Configuration & Colors ---
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
error()   { echo -e "${RED}[ERROR]${NC} $1"; exit 1; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

if [[ $EUID -ne 0 ]]; then
   error "This script must be run as root. Try: sudo $0"
fi

info "Uninstalling kprotect..."

# 1. Stop and Disable Service
if systemctl is-active --quiet kprotect; then
    info "Stopping kprotect service..."
    systemctl stop kprotect
fi

if systemctl is-enabled --quiet kprotect; then
    info "Disabling kprotect service..."
    systemctl disable kprotect
fi

# 2. Remove Systemd Unit
if [ -f "/etc/systemd/system/kprotect.service" ]; then
    rm /etc/systemd/system/kprotect.service
    systemctl daemon-reload
    info "Removed systemd unit."
fi

# 3. Remove Binaries
if [ -f "/usr/bin/kprotect-daemon" ]; then
    rm /usr/bin/kprotect-daemon
    info "Removed kprotect-daemon binary."
fi

if [ -f "/usr/bin/kprotect-cli" ]; then
    rm /usr/bin/kprotect-cli
    info "Removed kprotect-cli binary."
fi

# 4. Remove Runtime Directory
if [ -d "/run/kprotect" ]; then
    rm -rf /run/kprotect
    info "Removed runtime directory."
fi

# 5. Remove Personal Data (Optional)
read -p "Do you want to remove all personal data (configurations, keys, logs)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf /var/lib/kprotect
    rm -rf /var/log/kprotect
    # Optional: cleanup legacy /etc/kprotect if it exists
    [ -d "/etc/kprotect" ] && rm -rf /etc/kprotect
    success "Personal data and logs removed."
else
    info "Personal data and logs preserved."
fi

success "Uninstallation complete."
