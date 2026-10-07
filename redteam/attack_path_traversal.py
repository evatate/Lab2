#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_path_traversal.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 6, 2026
#
# Description:   Path traversal in several encodings, dotfile access, and
#                attempts to read the server's own source.
#
# Usage:         python3 redteam/attack_path_traversal.py [host] [port]
#
# ==============================================================================

"""
Every target below must never return file contents; the expected code
differs by case since not every rejection reason is "forbidden":
1. /../server.py                              literal ../          -> 403
2. /..%2f..%2fetc%2fpasswd                    percent-encoded ../   -> 403
3. /%252e%252e%252f...                        double-encoded ../    -> 403
   (path resolution itself only decodes once, so this would otherwise
   resolve to the inert literal filename "%2e%2e%2f...passwd" and 404 --
   but a second, detection-only decode catches that a further decode
   would reveal "../../etc/passwd" and rejects it outright instead)
4. /helloworld.html%00.txt                    null byte             -> 403
5. /.gitignore                                dotfile               -> 403
6. /server.py                                 server source         -> 403
7. /                                          bare directory        -> 404
"""

from util import report, send_raw, server_addr


def main():
    host, port = server_addr()

    cases = [
        ("literal ../", "/../server.py"),
        ("percent-encoded ../ (%2e%2e%2f)", "/..%2f..%2fetc%2fpasswd"),
        ("double-encoded ../ (%252e%252e%252f)",
         "/%252e%252e%252f%252e%252e%252fetc%252fpasswd"),
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
