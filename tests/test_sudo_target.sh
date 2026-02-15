#!/bin/bash
SOCKET_PATH="/run/kprotect/kprotect.sock"

# 1. Start a real process so the daemon knows the PID
sleep 100 &
TARGET_PID=$!
echo "Spawned process $TARGET_PID"

# 2. Subscribe in background
(
    echo "SUBSCRIBE"
    sleep 3
) | socat - UNIX-CONNECT:$SOCKET_PATH > /tmp/sudo_feed_output.txt &
PID_SUB=$!

# 3. Send CHECK_SUDO with target command
# Simulate: PID $TARGET_PID wants to run "cat"
sleep 1
echo "CHECK_SUDO $TARGET_PID cat" | socat - UNIX-CONNECT:$SOCKET_PATH

# 4. Wait and check output
sleep 2
kill $PID_SUB 2>/dev/null
kill $TARGET_PID 2>/dev/null

echo "--- Feed Output ---"
cat /tmp/sudo_feed_output.txt
echo "-------------------"

if grep -q "cat" /tmp/sudo_feed_output.txt && grep -q "\"pid\":$TARGET_PID" /tmp/sudo_feed_output.txt; then
    echo "✅ SUCCESS: Daemon processed target command 'cat' for PID $TARGET_PID"
else
    echo "❌ FAILURE: Target command 'cat' not found in event feed"
fi
