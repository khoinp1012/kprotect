#!/bin/bash
set -e

# --- Configuration & Colors ---
GREEN='\033[0;32m'
BLUE='\033[0;34m'
NC='\033[0m'

info()    { echo -e "${BLUE}[INFO]${NC}  $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Resolve project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"

# Check if cargo-deb is installed
if ! cargo deb --version &> /dev/null; then
    info "cargo-deb not found. Installing..."
    cargo install cargo-deb
fi

# 1. Build Binaries
info "Cleaning previous builds..."
cargo clean

info "Building release binaries..."
cargo build --release

# 2. Build Debian Package
info "Packaging .deb..."
cd kprotect-daemon
cargo deb --no-build --output ../target/kprotect.deb
cd ..

# 3. Result
if [ -f "target/kprotect.deb" ]; then
    success "Package created at target/kprotect.deb"
    dpkg-deb --info target/kprotect.deb
else
    echo -e "${RED}[ERROR]${NC} Failed to create .deb file"
    exit 1
fi
