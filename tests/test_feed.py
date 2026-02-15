#!/usr/bin/env python3
import socket
import os
import time
import json
import sys

SOCKET_PATH = "/run/kprotect/kprotect.sock"

def test_feed():
    if not os.path.exists(SOCKET_PATH):
        print(f"Error: Socket {SOCKET_PATH} not found.")
        sys.exit(1)

    print(f"Connecting to {SOCKET_PATH}...")
    client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    client.connect(SOCKET_PATH)

    # 1. Subscribe
    print("Sending: SUBSCRIBE")
    client.sendall(b"SUBSCRIBE\n")
    
    # Read initial response (should be OK)
    # We read in a loop because we might get partial reads
    response = client.recv(4096).decode('utf-8')
    print(f"Received: {response.strip()}")

    # 2. Trigger Event
    pid = os.getpid()
    print(f"Sending: CHECK_SUDO {pid}")
    client.sendall(f"CHECK_SUDO {pid}\n".encode('utf-8'))

    # 3. Read loop to catch the event and the command response
    # The event comes async in batches. The command response comes immediately.
    client.settimeout(2.0)
    buffer = ""
    try:
        start_time = time.time()
        while time.time() - start_time < 2.0:
            chunk = client.recv(4096).decode('utf-8')
            if not chunk:
                break
            buffer += chunk
            print(f"Chunk received: {chunk.strip()}")
            
            if "target" in chunk and "Sudo Bypass" in chunk:
                print("\n✅ SUCCESS: Caught 'Sudo Bypass' event in feed!")
            if "DENY" in chunk or "Authorized" in chunk:
                print("\n✅ SUCCESS: Caught Command Response!")
                
    except socket.timeout:
        print("\nTimeout waiting for data.")
    except Exception as e:
        print(f"\nError: {e}")
    finally:
        client.close()

if __name__ == "__main__":
    test_feed()
