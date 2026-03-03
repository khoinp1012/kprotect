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
    warn "BPF LSM is NOT enabled. kprotect requires it to function."
    
    # Suggest GRUB fix
    if [ -f "/etc/default/grub" ]; then
        info "Generating recovery command..."
        # Extract current GRUB parameters more robustly
        LINE=$(grep "^GRUB_CMDLINE_LINUX_DEFAULT=" /etc/default/grub)
        # Extract everything between the first set of quotes (single or double)
        CURRENT_PARAMS=$(echo "$LINE" | sed -E "s/GRUB_CMDLINE_LINUX_DEFAULT=['\"](.*)['\"]/\1/")
        
        # If extraction failed (e.g. no quotes), fallback to empty
        if [ "$CURRENT_PARAMS" == "$LINE" ]; then
            CURRENT_PARAMS=""
        fi

        # Refine parameters: remove existing lsm= member and append new one at the end
        NEW_PARAMS=$(echo "$CURRENT_PARAMS" | sed -E 's/lsm=[^ "]*//')
        NEW_PARAMS="$NEW_PARAMS lsm=lockdown,capability,landlock,yama,apparmor,bpf"
        
        # Clean up double spaces and leading/trailing whitespace
        NEW_PARAMS=$(echo "$NEW_PARAMS" | sed 's/  */ /g' | sed 's/^ //;s/ $//')

        # Detect boot mode
        BOOT_MODE="BIOS"
        [ -d /sys/firmware/efi ] && BOOT_MODE="UEFI"
        info "Detected boot mode: $BOOT_MODE"

        # Detect GRUB update command
        GRUB_UPDATE_CMD=""
        if command -v update-grub &> /dev/null; then
            GRUB_UPDATE_CMD="update-grub"
        elif command -v update-grub2 &> /dev/null; then
            GRUB_UPDATE_CMD="update-grub2"
        elif command -v grub-mkconfig &> /dev/null; then
            # Try to find config path
            GRUB_CFG_PATH="/boot/grub/grub.cfg"
            [ -f "/boot/efi/EFI/ubuntu/grub.cfg" ] && GRUB_CFG_PATH="/boot/efi/EFI/ubuntu/grub.cfg"
            GRUB_UPDATE_CMD="grub-mkconfig -o $GRUB_CFG_PATH"
        fi

        echo ""
        echo -e "${YELLOW}Run this command and then RESTART YOUR COMPUTER:${NC}"
        echo "--------------------------------------------------------------------------------"
        if [ -n "$GRUB_UPDATE_CMD" ]; then
            echo "sudo sed -i -E \"s/GRUB_CMDLINE_LINUX_DEFAULT=(['\\\"])(.*)(['\\\"])/GRUB_CMDLINE_LINUX_DEFAULT=\\1\\2 lsm=lockdown,capability,landlock,yama,apparmor,bpf\\3/\" /etc/default/grub && sudo $GRUB_UPDATE_CMD"
        else
            echo "1. Edit /etc/default/grub"
            echo "2. Add 'lsm=lockdown,capability,landlock,yama,apparmor,bpf' to GRUB_CMDLINE_LINUX_DEFAULT"
            echo "3. Run your system's GRUB update command and reboot."
        fi
        echo "--------------------------------------------------------------------------------"
        echo ""
    fi
    
    error "BPF LSM is not enabled. Please run the command above and reboot."
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

# Install PAM module
if [ -f "target/release/libkprotect_pam.so" ]; then
    info "Installing PAM module to system security directories..."
    for dir in "/lib/x86_64-linux-gnu/security" "/usr/lib/security" "/lib/security"; do
        if [ -d "$dir" ]; then
            install -m 644 target/release/libkprotect_pam.so "$dir/pam_kprotect.so"
            success "Installed to $dir/pam_kprotect.so"
        fi
    done

    # Register in /etc/pam.d/sudo
    if [ -f "/etc/pam.d/sudo" ]; then
        if ! grep -q "pam_kprotect.so" /etc/pam.d/sudo; then
            info "Registering kprotect in /etc/pam.d/sudo..."
            # Insert at the top (after the first line or directly at top)
            # Using sed to insert at the 2nd line to avoid replacing the header
            sed -i '2i auth sufficient pam_kprotect.so' /etc/pam.d/sudo
            success "Registered Quick Sudo bypass in /etc/pam.d/sudo"
        else
            info "kprotect already registered in /etc/pam.d/sudo"
        fi
    else
        warn "/etc/pam.d/sudo not found. Quick Sudo bypass must be configured manually."
    fi
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

