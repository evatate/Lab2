#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/util.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
#
# Description:   Shared helpers for the red-team attack scripts: send raw
#                bytes over a fresh TCP socket and print what came back.
#
# ==============================================================================

import socket
import sys


def send_raw(payload, host="localhost", port=8080, timeout=5, recv_size=65536):
    """Opens a new TCP connection, sends exactly `payload`, and returns
    whatever bytes come back before the timeout (or b"<TIMEOUT>" /
    b"<CLOSED>" as sentinels)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    s.connect((host, port))
    try:
        s.sendall(payload)
    except (BrokenPipeError, ConnectionResetError):
        return b"<CLOSED-DURING-SEND>"
    try:
        data = s.recv(recv_size)
        if not data:
            return b"<CLOSED>"
        return data
    except socket.timeout:
        return b"<TIMEOUT>"
    finally:
        s.close()


def report(title, payload, response, note=""):
    print(f"\n===== {title} =====")
    print("--- bytes sent ---")
    print(payload.decode("latin-1", errors="replace"))
    print("--- response ---")
    print(response.decode("latin-1", errors="replace")[:500])
    if note:
        print(f"--- note --- \n{note}")


def server_addr():
    """host, port from argv, defaulting to localhost:8080."""
    host = sys.argv[1] if len(sys.argv) > 1 else "localhost"
    port = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
    return host, port
