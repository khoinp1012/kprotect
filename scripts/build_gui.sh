#!/bin/bash
set -e

echo "Building kprotect GUI for release..."

# Resolve project root
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_ROOT"
echo "Project Root: $PROJECT_ROOT"

# Build GUI
echo "Building GUI..."
cd kprotect-ui
if [ ! -d "node_modules" ]; then
    echo "Installing UI dependencies..."
    npm install
fi
npm run tauri build
cd ..

echo "✓ GUI Build Complete!"
echo "  - GUI: kprotect-ui/src-tauri/target/release/bundle/"
