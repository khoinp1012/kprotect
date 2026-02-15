#!/bin/bash
SOCKET="/run/kprotect/kprotect.sock"

if [ ! -S "$SOCKET" ]; then
    echo "❌ Socket not found at $SOCKET. Is the daemon running?"
    exit 1
fi

echo "--- 🛡️ Privilege Guard Verification ---"

# 1. Add a dummy sudo rule
# Pattern: systemd -> bash
echo "Adding test sudo rule: /usr/lib/systemd/systemd,/bin/bash"
echo "SUDO_ADD;/usr/lib/systemd/systemd,/bin/bash;Test Rule" | socat - UNIX-CONNECT:$SOCKET

# 2. List rules
echo -e "\nCurrent Sudo Rules:"
echo "SUDO_LIST" | socat - UNIX-CONNECT:$SOCKET

# 3. Test CHECK_SUDO (This will likely fail if PID isn't in cache, but let's try our own PID)
MY_PID=$$
echo -e "\nChecking sudo for current PID ($MY_PID):"
echo "CHECK_SUDO $MY_PID" | socat - UNIX-CONNECT:$SOCKET

echo -e "\n--- End Verification ---"
