#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_protocol_edges.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 6, 2026
#
# Description:   Protocol-level edge cases: missing/duplicate Host, an
#                unrecognized HTTP version, and an unsupported method that
#                still carries a body which must be correctly consumed.
#
# Usage:         python3 redteam/attack_protocol_edges.py [host] [port]
#
# ==============================================================================

"""
1. no Host header -> 400
2. two Host headers -> 400
3. HTTP/9.9 -> 505
4. POST with a body plus a pipelined GET -> 501 and close, GET never read
"""

from util import report, send_raw, server_addr


def main():
    host, port = server_addr()

    payload = b"GET /helloworld.html HTTP/1.1\r\n\r\n"
    report("missing Host header", payload, send_raw(payload, host, port))

    payload = b"GET /helloworld.html HTTP/1.1\r\nHost: localhost\r\nHost: evil.example\r\n\r\n"
    report("duplicate Host headers", payload, send_raw(payload, host, port))

    payload = b"GET /helloworld.html HTTP/9.9\r\nHost: localhost\r\n\r\n"
    report("unsupported HTTP version", payload, send_raw(payload, host, port))

    payload = (
        b"POST /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 11\r\n"
        b"\r\n"
        b"hello world"
        b"GET /english_words.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    report(
        "unsupported method (POST) with body + pipelined GET",
        payload,
        send_raw(payload, host, port),
        note="Server must not desync onto the pipelined GET after rejecting the POST.",
    )


if __name__ == "__main__":
    main()
