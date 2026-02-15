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
cd "$PROJECT_ROOT/kprotect-daemon"

info "Running lineage cache stress and accuracy tests..."

if cargo test --test lineage_test -- --nocapture; then
    success "All lineage tests passed!"
else
    error "Lineage tests failed."
fi

info "Checking build integrity (daemon)..."
if cargo check -p kprotect-daemon; then
    success "Daemon build check passed."
else
    error "Daemon build check failed."
fi

info "Checking build integrity (common)..."
if cargo check -p kprotect-common; then
    success "Common build check passed."
else
    error "Common build check failed."
fi

success "All verifications complete!"
