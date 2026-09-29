#!/usr/bin/env python3

# ==============================================================================
# File Name:     client.py
# Author:        Eva Tate
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer -- Hardened Web Server Lab
# Date:          September 29, 2026
#
# Description:   A minimal command-line HTTP/1.1 client. Sends a single GET
#                request over a raw TCP socket and prints the full response
#                (status line, headers, body), looping on recv() until the
#                whole response -- however many packets it took -- has
#                arrived.
#
# ==============================================================================

"""HTTP/1.1 command-line client.

Usage: python3 client.py <server_host> <server_port> <path>
"""

import socket
import sys

RECV_CHUNK = 4096


def recv_until(sock, buf, delim):
    while True:
        idx = buf.find(delim)
        if idx != -1:
            return bytes(buf[:idx]), buf[idx + len(delim) :]
        data = sock.recv(RECV_CHUNK)
        if not data:
            return bytes(buf), b""
        buf += data


def recv_exact(sock, buf, n):
    while len(buf) < n:
        data = sock.recv(RECV_CHUNK)
        if not data:
            break
        buf += data
    return bytes(buf[:n]), buf[n:]


def parse_headers(header_block):
    lines = header_block.split(b"\r\n")
    status_line = lines[0]
    headers = {}
    for line in lines[1:]:
        if b":" not in line:
            continue
        name, value = line.split(b":", 1)
        headers[name.strip().lower().decode("latin-1")] = value.strip().decode("latin-1")
    return status_line, headers


def fetch(host, port, path):
    if not path.startswith("/"):
        path = "/" + path

    request = (
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}:{port}\r\n"
        f"User-Agent: cs60-lab2-client/1.0\r\n"
        f"Connection: close\r\n"
        f"\r\n"
    ).encode("latin-1")

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((host, port))
    sock.sendall(request)

    buf = b""
    header_block, buf = recv_until(sock, buf, b"\r\n\r\n")
    status_line, headers = parse_headers(header_block)

    body = b""
    if "content-length" in headers:
        length = int(headers["content-length"])
        body, buf = recv_exact(sock, buf, length)
    elif headers.get("transfer-encoding", "").lower() == "chunked":
        body = read_chunked(sock, buf)
    else:
        # No length given: read until the server closes the connection.
        while True:
            data = sock.recv(RECV_CHUNK)
            if not data:
                break
            buf += data
        body = buf

    sock.close()
    return status_line, headers, body


def read_chunked(sock, buf):
    body = b""
    while True:
        size_line, buf = recv_until(sock, buf, b"\r\n")
        size = int(size_line.split(b";")[0].strip(), 16)
        if size == 0:
            break
        chunk, buf = recv_exact(sock, buf, size)
        body += chunk
        # consume the trailing CRLF after the chunk
        while len(buf) < 2:
            data = sock.recv(RECV_CHUNK)
            if not data:
                break
            buf += data
        buf = buf[2:]
    return body


def main():
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <server_host> <server_port> <path>", file=sys.stderr)
        sys.exit(1)

    host = sys.argv[1]
    port = int(sys.argv[2])
    path = sys.argv[3]

    status_line, headers, body = fetch(host, port, path)

    sys.stdout.buffer.write(status_line + b"\r\n")
    for name, value in headers.items():
        sys.stdout.buffer.write(f"{name}: {value}\r\n".encode("latin-1"))
    sys.stdout.buffer.write(b"\r\n")
    sys.stdout.buffer.write(body)
    sys.stdout.buffer.write(b"\n")
    sys.stdout.buffer.flush()

    print(f"\n[client] received {len(body)} body bytes", file=sys.stderr)


if __name__ == "__main__":
    main()
