#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_protocol_edges.py
# Author:        Eva Tate
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
#
# Description:   Protocol-level edge cases: missing/duplicate Host, an
#                unrecognized HTTP version, and an unsupported method that
#                still carries a body which must be correctly consumed.
#
# Usage:         python3 redteam/attack_protocol_edges.py [host] [port]
#
# ==============================================================================

"""
What each attack does and why it matters
-----------------------------------------

1. missing_host: HTTP/1.1 requires exactly one Host header; a request
   without one is malformed. Expected/observed: 400.

2. duplicate_host: two Host headers is also ambiguous (which one does the
   server act on?) and must be rejected the same way conflicting
   Content-Length headers are. Expected/observed: 400.

3. unsupported_version: "HTTP/9.9" is a recognizable version token the
   server simply doesn't support, distinct from a malformed one. Expected:
   505 (not 400 -- the request line itself parses fine). Observed: 505.

4. unsupported_method_with_body: a POST that carries a real
   Content-Length'd body. The field guide is explicit that "reject the
   method" is not itself a defense -- a server that drops a POST without
   reading its declared body will desync the *next* request on this
   keep-alive connection. This test pipelines a second, legitimate GET right
   after the POST + body to check for exactly that. Expected: the POST gets
   501 and the connection is closed outright (this server's chosen defense:
   close on anything it declines, per the lab's explicit allowance), so the
   pipelined GET is never read at all rather than being misparsed. Observed:
   501, connection closed; the trailing GET bytes are simply discarded when
   the socket closes -- no partial/garbled response is ever sent for them.
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
