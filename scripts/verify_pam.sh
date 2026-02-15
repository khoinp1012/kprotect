#!/bin/bash
SOCKET="/run/kprotect/kprotect.sock"
USER=$(whoami)

echo "--- 🛡️ Full PAM Bypass Verification ---"

# 1. Spawn a subshell to get a clean, complete lineage
echo "[1] Spawning subshell to capture lineage..."
(
    # We are in a subshell. Wait a bit for daemon to process BIRTH events.
    sleep 1
    MY_PID=$$
    echo "Subshell PID: $MY_PID"
    
    # 2. Get the chain from daemon (we'll use a hack to get it by parsing logs if needed, 
    # but let's try to infer it: parent should be this script, grandparent is previous bash, etc.)
    # Actually, let's just use the 'SUDO_LIST' after trying to 'CHECK_SUDO' once to see it in logs.
    
    echo "[2] Triggering a check to force daemon to build the chain (expected to fail initially)..."
    echo "CHECK_SUDO $MY_PID" | socat - UNIX-CONNECT:$SOCKET
    
    # 3. Extract the chain from journal logs
    echo "[3] Extracting chain from journal..."
    CHAIN=$(sudo journalctl -u kprotect -n 20 --no-pager | grep "Sudo check for PID $MY_PID denied: Incomplete" | sed -n "s/.*: (\(.*\))/\1/p" | tail -n 1)
    
    if [ -z "$CHAIN" ]; then
        echo "❌ Could not find chain for PID $MY_PID in logs."
        exit 1
    fi
    echo "Found chain: $CHAIN"
    
    # 4. Authorize this exact chain
    echo "[4] Authorizing chain: $CHAIN"
    # Convert "a -> b -> c" to "a,b,c" for SUDO_ADD
    COMMA_CHAIN=$(echo "$CHAIN" | sed "s/ -> /,/g")
    echo "SUDO_ADD;$COMMA_CHAIN;Test Bypass for Subshell" | socat - UNIX-CONNECT:$SOCKET
    
    # 5. Verify via pamtester
    echo "[5] Verifying PAM bypass via pamtester..."
    # pamtester <service> <user> <action>
    # If successful, it should NOT ask for password and return 0.
    pamtester kprotect-test $USER authenticate
    if [ $? -eq 0 ]; then
        echo "✅ SUCCESS: PAM Bypass granted for $MY_PID"
    else
        echo "❌ FAILURE: PAM Bypass denied"
    fi
    
)
