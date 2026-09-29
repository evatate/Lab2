#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_path_traversal.py
# Author:        Eva Tate
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
#
# Description:   Path traversal in several encodings, dotfile access, and
#                attempts to read the server's own source.
#
# Usage:         python3 redteam/attack_path_traversal.py [host] [port]
#
# ==============================================================================

"""
What each attack does and why it matters
-----------------------------------------

1. literal_dotdot: GET /../server.py -- the plain, unencoded traversal.
2. percent_encoded_dotdot: GET /..%2f..%2fetc%2fpasswd -- '%2f' is '/' and
   '%2e' is '.'; a server that only string-matches "../" before decoding
   percent-escapes misses this.
3. double_encoded_dotdot: GET /%2e%2e%2f%2e%2e%2fetc%2fpasswd -- relies on
   the request passing through two decode passes (e.g. a proxy then the
   origin server). Our server decodes exactly once, which is the spec-
   correct behavior, so a double-encoded payload just fails to resolve to
   any real file rather than escaping the directory.
4. null_byte: GET /helloworld.html%00.txt -- historically used to trick
   C-string-based file checks into stopping early. Python strings aren't
   NUL-terminated so this isn't exploitable the same way here, but it should
   still be rejected outright rather than silently accepted.
5. dotfile: GET /.gitignore -- a legitimate file that lives inside the
   served directory but should not be exposed.
6. own_source: GET /server.py -- reading the server's own implementation.
7. directory: GET / -- requesting the served directory itself rather than a
   file in it.

Expected for all seven: 403 (or 404 for the bare directory request, which
this server treats as "no file named"), never 200 and never the actual file
contents.

Observed: all seven return 403 except the bare "/" request, which returns
404 (there is no index file, so "no file was requested" is reported as Not
Found rather than Forbidden -- a deliberate choice, see README).
"""

from util import report, send_raw, server_addr


def main():
    host, port = server_addr()

    cases = [
        ("literal ../", "/../server.py"),
        ("percent-encoded ../ (%2e%2e%2f)", "/..%2f..%2fetc%2fpasswd"),
        ("double-encoded ../ (%252e...)", "/%2e%2e%2f%2e%2e%2fetc%2fpasswd"),
        ("null byte", "/helloworld.html%00.txt"),
        ("dotfile", "/.gitignore"),
        ("own source", "/server.py"),
        ("bare directory request", "/"),
    ]

    for label, target in cases:
        payload = f"GET {target} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n".encode()
        report(label, payload, send_raw(payload, host, port))


if __name__ == "__main__":
    main()
