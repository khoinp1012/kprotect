#!/usr/bin/env python3
import socket
import sys

SOCKET_PATH = "/run/kprotect/kprotect.sock"

def test_ping():
    try:
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        client.connect(SOCKET_PATH)
        print("Connected.")
        
        print("Sending: PING")
        client.sendall(b"PING\n")
        
        response = client.recv(4096).decode('utf-8')
        print(f"Received: {response.strip()}")
        client.close()
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    test_ping()
