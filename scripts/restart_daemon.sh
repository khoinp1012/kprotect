#!/bin/bash
# Restart kprotect-daemon safely to pick up new changes

echo "🛑 Stopping existing kprotect-daemon..."
sudo killall kprotect-daemon 2>/dev/null

# Clean up stale files
sudo rm -f /run/kprotect/kprotect.sock
sudo rm -f /run/kprotect/kprotect.pid

echo "🚀 Starting kprotect-daemon in background..."
sudo kprotect-daemon daemon > /var/log/kprotect/daemon.log 2>&1 &

echo "✅ Daemon started. Logs are at /var/log/kprotect/daemon.log"
