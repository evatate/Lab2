#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_framing.py
# Author:        Eva Tate and Giselle Wu
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
#
# Description:   Request-smuggling / framing attacks: conflicting
#                Content-Length headers, Content-Length next to
#                Transfer-Encoding, bare CR/LF line endings, a body longer
#                than declared with a pipelined follow-up request, malformed
#                chunked encoding, and a header-name whitespace trick.
#
# Usage:         python3 redteam/attack_framing.py [host] [port]
#
# ==============================================================================

"""
What each attack does and why it matters
-----------------------------------------

1. conflicting_content_length: sends two Content-Length headers with
   different values. A server that picks the wrong one -- or reads the
   headers again with a different parser than the one that later reads the
   body -- will desync on which bytes belong to this request's body versus
   the start of the next one. This is the textbook CL.CL smuggling primitive.
   Expected: 400, connection closed. Observed: 400, "multiple Content-Length
   headers" -- the server refuses to pick a side.

2. cl_te_smuggling: sends both Content-Length and Transfer-Encoding: chunked
   on the same request. Real front-end/back-end server pairs disagree about
   which one wins, which is the whole basis of CL.TE / TE.CL smuggling.
   Expected: 400. Observed: 400, "Content-Length and Transfer-Encoding both
   present".

3. bare_line_endings: uses a lone \n (no \r) as the line terminator. RFC 9112
   requires CRLF; a parser that accepts bare LF disagrees with one that
   doesn't about where a line ends, which is itself a desync vector between
   two servers in a chain. Expected: 400. Observed: 400, "bare LF in
   request" -- but see NOTES.md for the version of this server that instead
   hung for 15 seconds before timing out. That earlier failure is the basis
   of the postmortem.

4. body_overrun_pipeline: declares Content-Length: 5 but sends 10 bytes of
   body, with a second, real GET request's bytes appended right after. If
   the server reads more than 5 bytes of "body", it swallows the start of
   the attacker's planted next request and may silently serve it as part of
   this connection, or -- worse -- if it reads *fewer* than the surplus, the
   leftover bytes corrupt the next parse. Expected: the server must consume
   exactly 5 bytes and treat the leftover "aaaaa" + pipelined request as
   whatever it actually is (garbage), never smuggling the clean pipelined
   GET through unnoticed. Observed: server served the first request 200 OK
   (correctly reading only 5 body bytes), then tried to parse "aaaaaGET
   /english_words.txt HTTP/1.1" as the next request line. That splits into
   3 space-separated tokens ("aaaaaGET", "/english_words.txt", "HTTP/1.1"),
   which is syntactically well-formed but has an unsupported "method" ->
   501, connection closed. The attacker's real pipelined GET was never
   served as such -- the corruption prevented the smuggle rather than
   enabling it.

5. malformed_chunked: sends a non-hex chunk-size line, and separately a
   chunk whose declared size doesn't line up with an actual CRLF terminator.
   Expected: 400 for both. Observed: 400, "malformed chunk size" and 400,
   "malformed chunk terminator".

6. header_whitespace_before_colon: sends "Content-Length : 5" (space before
   the colon). RFC 9112 explicitly forbids whitespace between a header name
   and its colon *because* some implementations strip it and some don't --
   two servers disagreeing on whether "Content-Length " and "Content-Length"
   are the same header name is itself a smuggling vector. This is a more
   obscure case a naive server (or an AI-generated one) is unlikely to
   think to reject. Expected/observed: 400, "whitespace before header
   colon".
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
        b"aaaaaaaaaa"  # 10 bytes, 5 more than declared
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
        b"5\r\nhelloXX0\r\n\r\n"  # missing the CRLF chunk terminator
    )
    report("malformed chunk terminator", payload, send_raw(payload, host, port))

    payload = (
        b"GET /helloworld.html HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length : 5\r\n"  # space before the colon
        b"\r\n"
        b"aaaaa"
    )
    report("whitespace before header colon", payload, send_raw(payload, host, port))


if __name__ == "__main__":
    main()
