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
Every target below should get 403 (404 for bare "/"), never file contents.
1. /../server.py                         literal ../
2. /..%2f..%2fetc%2fpasswd               percent-encoded
3. /%2e%2e%2f%2e%2e%2fetc%2fpasswd       double-encoded, decoded only once so it won't match a file
4. /helloworld.html%00.txt               null byte, rejected outright
5. /.gitignore                           dotfile
6. /server.py                            server source
7. /                                     directory, 404 since no file named
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
