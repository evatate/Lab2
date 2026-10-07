#!/usr/bin/env python3

# ==============================================================================
# File Name:     server.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 6, 2026
#
# Description:   From-scratch HTTP/1.1 GET server on raw sockets, hardened
#                against smuggling, Slowloris, big input and path traversal.
#
# ==============================================================================

"""Hardened HTTP/1.1 server. Usage: python3 server.py <port>"""

import os
import re
import socket
import sys
import threading
import time
import urllib.parse

# limits on untrusted input
MAX_CONNECTIONS = 500          # concurrent connections
HEADER_TIMEOUT = 15.0          # secs to finish request line + headers
BODY_TIMEOUT = 30.0            # secs to read the declared body
IDLE_TIMEOUT = 20.0            # secs to wait for next keep-alive request
WRITE_TIMEOUT = 60.0           # secs to flush a response; own deadline, not
                               # whatever was left on the read-side timer
RECV_CHUNK = 4096

MAX_REQUEST_LINE = 8192        # -> 414 URI Too Long
MAX_HEADER_LINE = 8192         # -> 431 Request Header Fields Too Large
MAX_HEADER_COUNT = 100         # -> 431
MAX_HEADER_BLOCK_BYTES = 65536 # request line + headers total -> 414/431
MAX_BODY_SIZE = 1024 * 1024     # 1 MiB -> 413
MAX_CHUNK_SIZE_LINE = 4096     # one chunk-size line

LISTEN_BACKLOG = 128

STATUS_REASONS = {
    200: "OK",
    400: "Bad Request",
    403: "Forbidden",
    404: "Not Found",
    408: "Request Timeout",
    413: "Content Too Large",
    414: "URI Too Long",
    431: "Request Header Fields Too Large",
    501: "Not Implemented",
    505: "HTTP Version Not Supported",
}

CONTENT_TYPES = {
    ".html": "text/html",
    ".htm": "text/html",
    ".txt": "text/plain",
    ".css": "text/css",
    ".js": "application/javascript",
    ".json": "application/json",
    ".png": "image/png",
    ".jpg": "image/jpeg",
    ".jpeg": "image/jpeg",
    ".gif": "image/gif",
}

TOKEN_RE = re.compile(rb"[!#$%&'*+.^_`|~0-9A-Za-z-]+")
VERSION_RE = re.compile(rb"^HTTP/(\d+)\.(\d+)$")


class HttpError(Exception):
    """Request rejected with this status code."""

    def __init__(self, code, message=""):
        super().__init__(message)
        self.code = code


class ConnectionClosed(Exception):
    """Peer closed the connection."""


class TimedOut(Exception):
    """Cumulative deadline elapsed."""


# one cumulative deadline, since a per-recv timeout doesn't stop a trickle attack

class BufferedReader:
    def __init__(self, sock):
        self.sock = sock
        self.buf = bytearray()

    def _fill(self, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimedOut()
        self.sock.settimeout(remaining)
        try:
            data = self.sock.recv(RECV_CHUNK)
        except socket.timeout:
            raise TimedOut()
        if not data:
            raise ConnectionClosed()
        self.buf.extend(data)

    def read_head_block(self, max_len, deadline):
        """Read request line + headers; reject bare CR/LF right away instead of waiting."""
        checked = 0
        while True:
            checked = _check_bare_terminators(self.buf, checked)
            idx = self.buf.find(b"\r\n\r\n")
            if idx != -1:
                head = bytes(self.buf[:idx])
                del self.buf[: idx + 4]
                return head
            if len(self.buf) > max_len:
                raise _classify_head_too_long(bytes(self.buf))
            self._fill(deadline)

    def read_until(self, delim, max_len, deadline, on_too_long):
        """Read up to delim; on_too_long(buf) supplies the error past max_len."""
        while True:
            idx = self.buf.find(delim)
            if idx != -1:
                line = bytes(self.buf[:idx])
                del self.buf[: idx + len(delim)]
                return line
            if len(self.buf) > max_len:
                raise on_too_long(bytes(self.buf))
            self._fill(deadline)

    def read_exact(self, n, deadline):
        while len(self.buf) < n:
            self._fill(deadline)
        data = bytes(self.buf[:n])
        del self.buf[:n]
        return data

    def has_buffered(self):
        return len(self.buf) > 0


# parsing

def _check_bare_terminators(buf, checked):
    """Scan buf for a bare LF/CR from `checked` on; return the new count.
    A trailing CR is rechecked next time, it may still become CRLF."""
    n = len(buf)
    i = checked
    while i < n:
        byte = buf[i]
        if byte == 0x0A:
            if i == 0 or buf[i - 1] != 0x0D:
                raise HttpError(400, "bare LF in request")
        elif byte == 0x0D:
            if i == n - 1:
                return i
            if buf[i + 1] != 0x0A:
                raise HttpError(400, "bare CR in request")
        i += 1
    return n


def _classify_head_too_long(raw_head):
    """Too long with no CRLF yet -> 414, else 431."""
    first_break = raw_head.find(b"\r\n")
    if first_break == -1 or first_break > MAX_REQUEST_LINE:
        return HttpError(414, "URI Too Long")
    return HttpError(431, "Request Header Fields Too Large")


def read_head(reader, deadline):
    """Return (request_line, header_lines)."""
    raw = reader.read_head_block(MAX_HEADER_BLOCK_BYTES, deadline)
    lines = raw.split(b"\r\n")

    # CR/LF left after the split means a bare terminator
    for line in lines:
        if b"\r" in line or b"\n" in line:
            raise HttpError(400, "bare CR or LF in request")

    if not lines or lines[0] == b"":
        raise HttpError(400, "empty request line")

    request_line = lines[0]
    header_lines = lines[1:]

    if len(request_line) > MAX_REQUEST_LINE:
        raise HttpError(414, "URI Too Long")
    if len(header_lines) > MAX_HEADER_COUNT:
        raise HttpError(431, "too many header fields")
    for h in header_lines:
        if len(h) > MAX_HEADER_LINE:
            raise HttpError(431, "header line too long")

    return request_line, header_lines


def parse_request_line(request_line):
    parts = request_line.split(b" ")
    if len(parts) != 3:
        raise HttpError(400, "malformed request line")
    method, target, version = parts
    if not method or not target or not version:
        raise HttpError(400, "malformed request line")

    m = VERSION_RE.match(version)
    if not m:
        raise HttpError(400, "malformed HTTP version")
    major, minor = int(m.group(1)), int(m.group(2))
    if (major, minor) not in ((1, 0), (1, 1)):
        raise HttpError(505, "unsupported HTTP version")

    return method.decode("latin-1"), target.decode("latin-1"), (major, minor)


def parse_headers(header_lines):
    """Lowercased name -> value; 400 on any ambiguity, never guess."""
    headers = {}
    host_seen = False
    content_length_seen = False
    transfer_encoding_seen = False

    for line in header_lines:
        # obs-fold is a smuggling vector
        if line[:1] in (b" ", b"\t"):
            raise HttpError(400, "obsolete line folding")

        colon = line.find(b":")
        if colon == -1:
            raise HttpError(400, "malformed header line")
        name_raw = line[:colon]
        value = line[colon + 1 :].strip(b" \t")

        # some servers strip this space and some don't
        if name_raw != name_raw.rstrip(b" \t"):
            raise HttpError(400, "whitespace before header colon")
        if not name_raw:
            raise HttpError(400, "empty header name")
        # names must be tokens
        if not TOKEN_RE.fullmatch(name_raw):
            raise HttpError(400, "invalid character in header name")

        name = name_raw.decode("latin-1").lower()
        value_str = value.decode("latin-1")

        if name == "host":
            if host_seen:
                raise HttpError(400, "multiple Host headers")
            host_seen = True
        elif name == "content-length":
            if content_length_seen:
                raise HttpError(400, "multiple Content-Length headers")
            content_length_seen = True
            if not re.fullmatch(r"[0-9]+", value_str):
                raise HttpError(400, "invalid Content-Length")
        elif name == "transfer-encoding":
            if transfer_encoding_seen:
                raise HttpError(400, "multiple Transfer-Encoding headers")
            transfer_encoding_seen = True
            if value_str.strip().lower() != "chunked":
                raise HttpError(400, "unsupported Transfer-Encoding")

        headers[name] = value_str

    if not host_seen:
        raise HttpError(400, "missing Host header")
    if content_length_seen and transfer_encoding_seen:
        # CL + TE is the smuggling ambiguity
        raise HttpError(400, "Content-Length and Transfer-Encoding both present")

    return headers


def consume_body(reader, headers, deadline):
    """Read and discard the body so keep-alive never parses it as the next request."""
    if "transfer-encoding" in headers:
        consume_chunked_body(reader, deadline)
        return
    if "content-length" in headers:
        length = int(headers["content-length"])
        if length > MAX_BODY_SIZE:
            raise HttpError(413, "body too large")
        reader.read_exact(length, deadline)


def consume_chunked_body(reader, deadline):
    total = 0
    while True:
        def too_long(_buf):
            return HttpError(431, "chunk size line too long")

        size_line = reader.read_until(b"\r\n", MAX_CHUNK_SIZE_LINE, deadline, too_long)
        size_field = size_line.split(b";", 1)[0]  # no whitespace allowed
        if not size_field or not re.fullmatch(rb"[0-9A-Fa-f]+", size_field):
            raise HttpError(400, "malformed chunk size")
        size = int(size_field, 16)

        total += size
        if total > MAX_BODY_SIZE:
            raise HttpError(413, "chunked body too large")

        if size == 0:
            # trailers, then a blank line
            trailer_bytes = 0
            while True:
                def trailer_too_long(_buf):
                    return HttpError(431, "trailers too large")

                trailer_line = reader.read_until(
                    b"\r\n", MAX_HEADER_LINE, deadline, trailer_too_long
                )
                trailer_bytes += len(trailer_line)
                if trailer_bytes > MAX_HEADER_BLOCK_BYTES:
                    raise HttpError(431, "trailers too large")
                if trailer_line == b"":
                    break
            return

        reader.read_exact(size, deadline)
        terminator = reader.read_exact(2, deadline)
        if terminator != b"\r\n":
            raise HttpError(400, "malformed chunk terminator")


# path safety

def safe_resolve_path(serve_dir, self_paths, raw_target):
    """Map target to a file in serve_dir or raise 400/403/404; decodes once only."""
    if not raw_target.startswith("/"):
        raise HttpError(400, "request-target must be origin-form")

    path_part = raw_target.split("?", 1)[0].split("#", 1)[0]

    try:
        decoded = urllib.parse.unquote(path_part, errors="strict")
    except (UnicodeDecodeError, ValueError):
        raise HttpError(400, "malformed percent-encoding")

    if "\x00" in decoded:
        raise HttpError(400, "null byte in request target")

    # still encoded after one decode: double-encoded traversal attempt
    again = urllib.parse.unquote(decoded)
    if again != decoded and (".." in again or "\\" in again or again.count("/") != decoded.count("/")):
        raise HttpError(403, "double-encoded path")

    candidate = os.path.realpath(os.path.join(serve_dir, decoded.lstrip("/")))

    if candidate != serve_dir and not candidate.startswith(serve_dir + os.sep):
        raise HttpError(403, "path escapes served directory")

    rel = os.path.relpath(candidate, serve_dir)
    if rel == ".":
        raise HttpError(404, "no file requested")

    if any(part.startswith(".") for part in rel.split(os.sep)):
        raise HttpError(403, "dotfile requested")

    if candidate in self_paths:
        raise HttpError(403, "server source requested")

    if os.path.isdir(candidate):
        raise HttpError(403, "directory requested")
    if not os.path.isfile(candidate):
        raise HttpError(404, "file not found")

    return candidate


# responses

def send_response(conn, code, body=b"", content_type="text/plain", connection="keep-alive"):
    reason = STATUS_REASONS[code]
    headers = [
        f"HTTP/1.1 {code} {reason}",
        f"Content-Type: {content_type}",
        f"Content-Length: {len(body)}",
        f"Connection: {connection}",
        "",
        "",
    ]
    conn.settimeout(WRITE_TIMEOUT)
    conn.sendall("\r\n".join(headers).encode("latin-1") + body)


def send_file_response(conn, path, connection):
    ext = os.path.splitext(path)[1].lower()
    content_type = CONTENT_TYPES.get(ext, "application/octet-stream")
    with open(path, "rb") as f:
        body = f.read()
    send_response(conn, 200, body, content_type, connection)


# per-connection handling

def handle_connection(conn, addr, serve_dir, self_paths, state=None):
    state = state if state is not None else {}
    reader = BufferedReader(conn)
    log = lambda msg: print(f"[{time.strftime('%H:%M:%S')}] {addr[0]}:{addr[1]} {msg}", flush=True)

    try:
        first_request = True
        while True:
            idle_deadline = time.monotonic() + (HEADER_TIMEOUT if first_request else IDLE_TIMEOUT)

            try:
                request_line, header_lines = read_head(reader, idle_deadline)
            except TimedOut:
                if reader.has_buffered():
                    # request in progress (Slowloris)
                    send_response(conn, 408, connection="close")
                    log("408 request timeout")
                # idle keep-alive expired, close quietly
                return
            except ConnectionClosed:
                return
            except HttpError as e:
                send_response(conn, e.code, connection="close")
                log(f"{e.code} while reading headers: {e}")
                return

            first_request = False
            body_deadline = time.monotonic() + BODY_TIMEOUT
            target = request_line.decode("latin-1", errors="replace")

            try:
                method, target, version = parse_request_line(request_line)
                headers = parse_headers(header_lines)
                consume_body(reader, headers, body_deadline)

                connection_header = headers.get("connection", "").strip().lower()
                if version == (1, 0):
                    # HTTP/1.0 defaults to close; keep-alive is opt-in
                    keep_alive = connection_header == "keep-alive"
                else:
                    keep_alive = connection_header != "close"

                if method != "GET":
                    send_response(conn, 501, connection="close")
                    log(f"501 unsupported method {method!r} for {target!r}")
                    return

                path = safe_resolve_path(serve_dir, self_paths, target)
                send_file_response(conn, path, "keep-alive" if keep_alive else "close")
                state["served"] = state.get("served", 0) + 1
                log(f"200 GET {target!r}")

            except TimedOut:
                send_response(conn, 408, connection="close")
                log("408 timeout reading body")
                return
            except ConnectionClosed:
                return
            except HttpError as e:
                send_response(conn, e.code, connection="close")
                log(f"{e.code} GET {target!r}: {e}")
                return

            if not keep_alive:
                return

    except Exception as e:  # noqa: BLE001 - keep server up
        log(f"unexpected error: {e!r}")
    finally:
        try:
            conn.close()
        except OSError:
            pass


SOURCE_EXTENSIONS = (".py", ".md")


def collect_source_paths(serve_dir):
    """All .py/.md files under serve_dir (blocked with 403)."""
    paths = set()
    for root, _dirs, files in os.walk(serve_dir):
        for name in files:
            if name.lower().endswith(SOURCE_EXTENSIONS):
                paths.add(os.path.realpath(os.path.join(root, name)))
    return paths


def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <port>", file=sys.stderr)
        sys.exit(1)
    try:
        port = int(sys.argv[1])
    except ValueError:
        print("port must be an integer", file=sys.stderr)
        sys.exit(1)

    serve_dir = os.path.realpath(os.getcwd())
    self_paths = collect_source_paths(serve_dir)

    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind(("", port))
    server_sock.listen(LISTEN_BACKLOG)
    print(f"Serving {serve_dir} on port {port}", flush=True)

    connection_slots = threading.Semaphore(MAX_CONNECTIONS)

    # live connections, so one can be evicted at capacity
    live = {}
    live_lock = threading.Lock()

    def worker(conn, addr, state):
        try:
            handle_connection(conn, addr, serve_dir, self_paths, state)
        finally:
            with live_lock:
                live.pop(conn, None)
            connection_slots.release()

    def evict_one():
        """Shut the oldest never-served connection (else oldest overall).
        Can hit a real slow client, but refusing everyone is worse."""
        with live_lock:
            if not live:
                return False
            victim = min(live.items(),
                         key=lambda kv: (kv[1].get("served", 0) > 0, kv[1]["t"]))[0]
        try:
            victim.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        return True

    try:
        while True:
            try:
                conn, addr = server_sock.accept()
            except OSError as e:
                # e.g. EMFILE, stay up
                print(f"accept() failed: {e!r}", flush=True)
                time.sleep(0.1)
                continue
            if not connection_slots.acquire(blocking=False):
                # at capacity: evict so dead connections can't lock out real clients
                if not (evict_one() and connection_slots.acquire(timeout=1.0)):
                    try:
                        conn.close()
                    except OSError:
                        pass
                    continue
            state = {"t": time.monotonic(), "served": 0}
            with live_lock:
                live[conn] = state
            threading.Thread(target=worker, args=(conn, addr, state), daemon=True).start()
    except KeyboardInterrupt:
        pass
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
