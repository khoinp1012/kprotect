#!/bin/bash

# Configuration
SOCKET_PATH="/run/kprotect/daemon.sock"

# Colors
GREEN='\033[0;32m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${GREEN}Testing Sudo Elevation Logic${NC}"

# 1. Get a valid PID (our own shell)
MY_PID=$$
echo "Using PID: $MY_PID"

# 2. Send CHECK_SUDO command
# The protocol is simple text over Unix socket
echo -e "${GREEN}Sending: CHECK_SUDO $MY_PID${NC}"

# Use socat to send and receive
if ! command -v socat &> /dev/null; then
    echo -e "${RED}socat not found. Installing...${NC}"
    sudo apt-get update && sudo apt-get install -y socat
fi

RESPONSE=$(echo "CHECK_SUDO $MY_PID" | socat - UNIX-CONNECT:$SOCKET_PATH)

echo -e "${GREEN}Response:${NC}"
echo "$RESPONSE"

if [[ "$RESPONSE" == *"DENY: PID not found"* ]]; then
     echo -e "${RED}Failed: PID not found in lineage cache. This is expected if the daemon hasn't seen this shell spawn.${NC}"
     echo "Try running a new process that the daemon *will* see, or restart the daemon to pick up existing processes if implemented."
elif [[ "$RESPONSE" == *"DENY"* ]]; then
     echo -e "${GREEN}Success: Logic executed (Denied as expected for unknown rule).${NC}"
elif [[ "$RESPONSE" == *"OK"* ]]; then
     echo -e "${GREEN}Success: Logic executed (Authorized - Unexpected unless you added a rule).${NC}"
else
     echo -e "${RED}Unknown response.${NC}"
fi
