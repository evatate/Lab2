#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_framing.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 6, 2026
#
# Description:   Request-smuggling and framing attacks (CL/TE conflicts, bare
#                CR/LF, body overrun, bad chunking, space before colon).
#
# Usage:         python3 redteam/attack_framing.py [host] [port]
#
# ==============================================================================

"""
1. two Content-Length headers (5 and 10) -> 400
2. Content-Length plus Transfer-Encoding: chunked -> 400
3. bare LF line endings -> 400 (see NOTES.md for the old 15s hang)
4. Content-Length: 5 with 10 body bytes and a pipelined GET -> 200, then 501 on the leftover
5. non-hex chunk size, and a missing chunk CRLF -> 400 for both
6. "Content-Length : 5" (space before colon) -> 400
"""

from util import report, send_raw, server_addr


def main():
    host, port = server_addr()

    report(
        "conflicting Content-Length",
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 5\r\n"
        b"Content-Length: 10\r\n"
        b"\r\n"
        b"aaaaaaaaaa",
        send_raw(
            b"GET /helloworld.html HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 5\r\n"
            b"Content-Length: 10\r\n"
            b"\r\n"
            b"aaaaaaaaaa",
            host,
            port,
        ),
    )

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 4\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"0\r\n\r\n"
    )
    report("Content-Length + Transfer-Encoding together", payload, send_raw(payload, host, port))

    payload = b"GET /helloworld.html HTTP/1.1\nHost: localhost\n\n"
    report("bare LF line endings", payload, send_raw(payload, host, port))

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n"
        b"aaaaaaaaaa"  # 10 bytes, 5 over
        b"GET /english_words.txt HTTP/1.1\r\nHost: localhost\r\n\r\n"
    )
    report(
        "body longer than declared + pipelined GET",
        payload,
        send_raw(payload, host, port),
        note="Server must not silently serve the pipelined GET as a clean second response.",
    )

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"ZZZ\r\nhello\r\n0\r\n\r\n"
    )
    report("malformed chunk size (non-hex)", payload, send_raw(payload, host, port))

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"\r\n"
        b"5\r\nhelloXX0\r\n\r\n"  # no CRLF after chunk
    )
    report("malformed chunk terminator", payload, send_raw(payload, host, port))

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length : 5\r\n"  # space before colon
        b"\r\n"
        b"aaaaa"
    )
    report("whitespace before header colon", payload, send_raw(payload, host, port))


if __name__ == "__main__":
    main()
