#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_resource_exhaustion.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
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
What each attack does and why it matters
-----------------------------------------

1. slowloris: opens several connections and trickles one byte of headers
   every 2 seconds, never sending the blank line that ends them. A server
   that resets its timeout on every successful recv() (rather than tracking
   one absolute deadline for finishing the headers) never times these out,
   because no single recv() call ever stalls long enough to trip a per-call
   timeout. Expected: each connection is cut off with 408 once the
   *cumulative* time to finish the headers exceeds the limit, regardless of
   how the bytes were paced. Observed: all 5 trickled connections received
   408 after ~15s (the server's HEADER_TIMEOUT), not 100s+ (which is how
   long trickling the full header line/byte-by-byte would otherwise take).

2. normal_client_during_attack: while the Slowloris connections above are
   still open and trickling, a normal client sends one ordinary request.
   Expected: it is served immediately, proving the attack doesn't block the
   accept loop or starve other threads. Observed: served in ~0.00s.

3. slow_body: declares Content-Length: 100 but sends only 5 bytes and then
   stops. Expected: 408 after BODY_TIMEOUT, not an indefinite hang.
   Observed: 408, "timeout reading body", after 30s.

4. oversized_uri / oversized_header_line / too_many_headers /
   oversized_content_length: blunt-force resource exhaustion via input size
   rather than time. Expected: 414 / 431 / 431 / 413 respectively, all
   without the server ever trying to buffer the full oversized input.
   Observed: matches expected codes.
"""

import threading
import time

from util import report, send_raw, server_addr


def slowloris(host, port, conn_id, results):
    import socket

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(20)
    s.connect((host, port))
    try:
        for b in b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\n":
            s.sendall(bytes([b]))
            time.sleep(2)
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
