#!/bin/bash
SOCKET="/tmp/kprotect.sock"

echo "--- GET_LOG_CONFIG ---"
echo "GET_LOG_CONFIG" | nc -U $SOCKET

echo -e "\n\n--- SET_LOG_RETENTION (Should fail as user) ---"
echo "SET_LOG_RETENTION;10;60" | nc -U $SOCKET

echo -e "\n\n--- GET_EVENTS (Should fail as user) ---"
echo "GET_EVENTS;5" | nc -U $SOCKET

echo -e "\n\n--- GET_AUDIT (Should fail as user) ---"
echo "GET_AUDIT;5" | nc -U $SOCKET

echo -e "\n\n--- HELP ---"
echo "HELP" | nc -U $SOCKET
