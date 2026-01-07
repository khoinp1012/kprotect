#!/bin/bash
set -e

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

# --- Pre-flight Checks ---
info "Starting pre-flight checks..."

# Check for required commands
for cmd in systemctl grep cp mkdir chmod install; do
    if ! command -v "$cmd" &> /dev/null; then
        error "Required command '$cmd' not found. Please install it."
    fi
done

# Detect if this is an update or fresh install
IS_UPDATE=false
SERVICE_WAS_RUNNING=false

if [ -f "/usr/bin/kprotect-daemon" ]; then
    IS_UPDATE=true
    info "Existing kprotect installation detected. Performing update..."
    
    # Check if service is running
    if systemctl is-active --quiet kprotect 2>/dev/null; then
        SERVICE_WAS_RUNNING=true
        info "Stopping kprotect service..."
        systemctl stop kprotect
    fi
else
    info "Performing fresh installation of kprotect..."
fi

# Resolve project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Check for BPF LSM support
echo -n -e "${BLUE}[INFO]${NC}  Checking for BPF LSM support... "
if grep -q "bpf" /sys/kernel/security/lsm 2>/dev/null; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED${NC}"
    error "BPF LSM is not enabled in your kernel. Verify boot parameters (lsm=...,bpf)."
fi

# --- Installation Steps ---
info "Creating directories..."
mkdir -p /var/lib/kprotect/configs /run/kprotect
chmod 700 /var/lib/kprotect/configs # Secure key storage
chmod 755 /run/kprotect  # Allow GUI to access socket

# Copy binaries
info "Copying binaries..."
if [ -f "target/release/kprotect" ]; then
    install -m 755 target/release/kprotect /usr/bin/kprotect-daemon
    success "Installed kprotect-daemon binary."
else
    error "kprotect binary not found in target/release/. Did you run 'cargo build --release'?"
fi

if [ -f "target/release/kprotect-cli" ]; then
    install -m 755 target/release/kprotect-cli /usr/bin/kprotect-cli
    success "Installed kprotect-cli binary."
else
    warn "kprotect-cli binary not found in target/release/."
fi



# Install Service
info "Installing systemd service..."
if [ -f "scripts/kprotect.service" ]; then
    install -m 644 scripts/kprotect.service /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable --now kprotect
    success "kprotect service enabled and started."
else
    error "scripts/kprotect.service not found."
fi

# --- Post-install ---
if [ "$IS_UPDATE" = true ]; then
    if [ "$SERVICE_WAS_RUNNING" = true ]; then
        info "Restarting kprotect service..."
        systemctl restart kprotect
        success "Service restarted successfully."
    else
        info "Service was not running before update. Use 'systemctl start kprotect' to start it."
    fi
    success "Update complete!"
else
    success "Installation complete!"
    info "Service is now running. Check status with: systemctl status kprotect"
    
    echo ""
    echo "================================================================================"
    echo " IMPORTANT: Please RESTART YOUR COMPUTER before authorizing any chain."
    echo " This ensures kprotect correctly tracks process lineage from boot."
    echo "================================================================================"
fi

