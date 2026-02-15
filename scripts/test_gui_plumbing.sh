#!/bin/bash
# kprotect GUI Plumbing Test Suite
# This script verifies the communication between the Daemon and the GUI.

SOCKET_PATH="/run/kprotect/kprotect.sock"

# Colors for output
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}🛡️ kprotect Diagnostic Tool${NC}"
echo "--------------------------------"

# 1. Check if socket exists
if [ -S "$SOCKET_PATH" ]; then
    echo -e "[PASS] Socket exists at $SOCKET_PATH"
else
    echo -e "[FAIL] Socket NOT found at $SOCKET_PATH"
    echo "Hint: Is the daemon running? Check 'sudo systemctl status kprotect' or 'ps aux | grep kprotect-daemon'"
    exit 1
fi

# 2. Verify basic connectivity (PING)
echo -n "Checking Daemon Connectivity (PING)... "
RESPONSE=$(echo "PING" | nc -U -w 2 "$SOCKET_PATH")
if [[ "$RESPONSE" == *"PONG"* ]]; then
    echo -e "${GREEN}OK (Received: $RESPONSE)${NC}"
else
    echo -e "${RED}FAILED (Received: $RESPONSE)${NC}"
    exit 1
fi

# 3. Verify Sudo Rules API
echo -n "Checking Sudo Rule Listing... "
RESPONSE=$(echo "SUDO_LIST" | nc -U -w 2 "$SOCKET_PATH")
if [[ "$RESPONSE" == *"OK"* ]]; then
    echo -e "${GREEN}OK${NC}"
else
    echo -e "${RED}FAILED (Received: $RESPONSE)${NC}"
fi

# 4. Mock a Real-time Elevation Event (Broadcast Test)
# This will test if the daemon can successfully broadcast to the event_tx pipe
echo -n "Triggering Mock Elevation Event... "
# Since we can't easily subscribe and send in one bash command with nc -U
# we'll use a python script or just verify if the daemon logs the event.
# For now, let's simulate a CHECK_SUDO call which we just updated in sudo.rs
PID=$$
echo "CHECK_SUDO $PID" | nc -U -w 1 "$SOCKET_PATH" > /dev/null
echo -e "${GREEN}Sent CHECK_SUDO for PID $PID${NC}"

echo "--------------------------------"
echo -e "${GREEN}Diagnostic Complete.${NC}"
echo "Next steps:"
echo "1. Run 'sudo systemctl restart kprotect' (or restart the daemon manually) to ensure new logic is active."
echo "2. Open the GUI to 'Security > Privilege Guard > Elevation Live Feed'."
echo "3. Run 'sudo cat /etc/shadow' in another terminal."
echo "4. Observe if the event appears in the GUI."
