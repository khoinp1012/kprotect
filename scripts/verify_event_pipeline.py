import socket
import json
import threading
import time
import os
import subprocess

SOCKET_PATH = "/run/kprotect/kprotect.sock"

def listen_to_events():
    """Subscribes to the daemon and prints received events."""
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(SOCKET_PATH)
            s.sendall(b"SUBSCRIBE\n")
            print("📡 Subscribed to real-time event stream...")
            
            # Read first line (OK: Subscribed...)
            s.recv(1024)
            
            while True:
                data = s.recv(4096)
                if not data:
                    break
                
                messages = data.decode().strip().split('\n')
                for msg in messages:
                    if not msg.strip(): continue
                    try:
                        event = json.loads(msg)
                        status = event.get('status')
                        pid = event.get('pid')
                        chain = event.get('chain_str') or ' -> '.join(event.get('chain', []))
                        details = event.get('details', '')
                        
                        icon = "🔒" if "Blocked" in status else "🔓"
                        print(f"[{time.strftime('%H:%M:%S')}] {icon} {status} | PID: {pid} | {chain} | {details}")
                    except json.JSONDecodeError:
                        print(f"❓ RAW DATA: {msg}")
    except Exception as e:
        print(f"❌ Error in listener: {e}")

if __name__ == "__main__":
    print("🛡️ kprotect Event Pipeline Tester v2")
    print("-----------------------------------")
    
    # Start subscriber thread
    listener = threading.Thread(target=listen_to_events, daemon=True)
    listener.start()
    
    time.sleep(1) # Wait for subscription to establish
    
    my_pid = os.getpid()
    print(f"\n🚀 Sending manual CHECK_SUDO for this script (PID: {my_pid})...")
    
    try:
        # Send a manual check for THIS process
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.connect(SOCKET_PATH)
            s.sendall(f"CHECK_SUDO {my_pid}\n".encode())
            resp = s.recv(1024).decode()
            print(f"   Daemon response: {resp.strip()}")
    except Exception as e:
        print(f"❌ Error sending command: {e}")

    print("\n-----------------------------------")
    print("👉 Now, open another terminal and run: sudo -K && sudo ls")
    print("   Observe if events appear below.")
    print("-----------------------------------")
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping...")
