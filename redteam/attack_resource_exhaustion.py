#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_resource_exhaustion.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 6, 2026
#
# Description:   Slowloris (trickled headers), a slow body, oversized
#                request line / headers / Content-Length, and confirmation
#                that a normal client is still served while the attack is
#                in progress.
#
# Usage:         python3 redteam/attack_resource_exhaustion.py [host] [port]
#
# ==============================================================================

"""
1. slowloris: 5 conns trickle 1 byte / 2s of headers -> 408 after ~15s total
2. normal client during the attack -> served right away
3. Content-Length: 100 but only 5 bytes sent -> 408 after BODY_TIMEOUT
4. oversized URI / header line / header count / Content-Length -> 414 / 431 / 431 / 413
"""

import threading
import time

from util import report, send_raw, server_addr


def slowloris(host, port, conn_id, results):
    import select
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((host, port))
    try:
        for b in b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\n":
            s.sendall(bytes([b]))
            # watch for the server giving up mid-trickle (it does, at ~15s)
            # instead of sleeping blind and then sending into a dead socket
            ready, _, _ = select.select([s], [], [], 2)
            if ready:
                results[conn_id] = s.recv(1024)
                return
        results[conn_id] = s.recv(1024)
    except (socket.timeout, ConnectionResetError, BrokenPipeError) as e:
        results[conn_id] = f"<{e!r}>".encode()
    finally:
        s.close()


def main():
    host, port = server_addr()

    print("===== slowloris (trickled headers) + normal client during attack =====")
    results = {}
    threads = [
        threading.Thread(target=slowloris, args=(host, port, i, results)) for i in range(5)
    ]
    start = time.time()
    for t in threads:
        t.start()

    time.sleep(3)
    t0 = time.time()
    normal_resp = send_raw(
        b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n",
        host,
        port,
    )
    print(f"normal client served in {time.time() - t0:.2f}s: {normal_resp[:20]!r}")

    for t in threads:
        t.join()
    print(f"slowloris connections resolved after {time.time() - start:.1f}s total:")
    for i, r in results.items():
        print(f"  conn {i}: {r!r}"[:120])

    payload = b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\n\r\nshort"
    report("slow / incomplete body (should 408, not hang)", payload, send_raw(payload, host, port, timeout=35))

    payload = b"GET /" + b"A" * 20000 + b" HTTP/1.1\r\nHost: localhost\r\n\r\n"
    report("oversized request-target (URI)", payload[:80] + b"...(truncated)...", send_raw(payload, host, port))

    payload = b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\nX-Big: " + b"B" * 20000 + b"\r\n\r\n"
    report("oversized single header line", payload[:80] + b"...(truncated)...", send_raw(payload, host, port))

    many_headers = b"".join(f"X-{i}: v\r\n".encode() for i in range(500))
    payload = b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\n" + many_headers + b"\r\n"
    report("thousands of headers", payload[:80] + b"...(truncated, 500 headers)...", send_raw(payload, host, port))

    payload = b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\nContent-Length: 999999999999\r\n\r\n"
    report("absurd Content-Length claim", payload, send_raw(payload, host, port))


if __name__ == "__main__":
    main()
