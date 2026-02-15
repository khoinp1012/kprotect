#!/bin/bash

# Configuration
SOCKET_PATH="/run/kprotect/kprotect.sock"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Testing Sudo Elevation Logic & Feed${NC}"

MY_PID=$$
echo "Using PID: $MY_PID"

# Use socat to send SUBSCRIBE then CHECK_SUDO
if ! command -v socat &> /dev/null; then
    echo -e "${RED}socat not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y socat
fi

# We use a subshell to send commands with delays to simulate a session
# 1. SUBSCRIBE to get events
# 2. CHECK_SUDO to trigger an event
# 3. Wait a bit to receive the event
# 4. Exit
(
    echo "SUBSCRIBE" 
    sleep 0.5
    echo "CHECK_SUDO $MY_PID"
    sleep 0.5
) | socat - UNIX-CONNECT:$SOCKET_PATH
