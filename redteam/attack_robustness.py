#!/usr/bin/env python3

# ==============================================================================
# File Name:     redteam/attack_robustness.py
# Author:        Eva Tate
# AI Assistance: Claude wrote the initial draft of this file; Eva
#                Tate tested, reviewed, and revised it.
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application layer: Hardened Web Server Lab
# Date:          October 7, 2026
#
# Description:   Odd attacks: disguised TE/CL values, chunk abuse, request-line
#                oddities, exotic traversal, pipelining, connection flood, slow
#                readers. Unexpected status or a smuggled reply is shown as LANDED.
#
# ==============================================================================

"""Usage: python3 redteam/attack_robustness.py [host] [port]"""

import socket
import sys
import threading
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "localhost"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
BIG = b"Content-Length: 4987770"   # marks the english_words.txt reply

seen_codes = {}
landed = []


def talk(raw, wait=4.0, chunks=None, delay=0.0):
    """Send raw bytes, return all replies until close or `wait`."""
    s = socket.create_connection((HOST, PORT), timeout=wait)
    try:
        if chunks:
            for c in chunks:
                s.sendall(c)
                time.sleep(delay)
        else:
            s.sendall(raw)
        data = b""
        end = time.time() + wait
        while time.time() < end:
            try:
                c = s.recv(65536)
            except socket.timeout:
                break
            if not c:
                break
            data += c
        return data
    except OSError as e:
        return repr(e).encode()
    finally:
        s.close()


def codes(data):
    out = []
    for part in data.split(b"HTTP/1.1 ")[1:]:
        try:
            out.append(int(part[:3]))
        except ValueError:
            pass
    return out


def check(name, raw, ok, forbid_big=True, **kw):
    data = talk(raw, **kw)
    cs = codes(data)
    for c in cs:
        seen_codes[c] = seen_codes.get(c, 0) + 1
    problems = []
    if not cs:
        # no reply is ok only if 0 (closed) is allowed
        if 0 not in ok:
            problems.append("no response")
    elif cs[0] not in ok:
        problems.append(f"first response {cs[0]} not in {sorted(ok)}")
    if 500 in cs:
        problems.append("500 from server")
    if forbid_big and BIG in data and "big_ok" not in kw:
        problems.append("smuggled/leaked big file served")
    tag = "PASS  " if not problems else "LANDED"
    if problems:
        landed.append(name)
    print(f"  {tag} {name:55s} -> {cs or 'closed'} {'; '.join(problems)}")


def get(path="/helloworld.html", ver="HTTP/1.1", hdrs="Host: x\r\n"):
    return f"GET {path} {ver}\r\n{hdrs}\r\n".encode()


SMUGGLE = b"GET /english_words.txt HTTP/1.1\r\nHost: x\r\n\r\n"
ERR = {400}
ERR_OR_CLOSE = {0, 400, 501}


def section(t):
    print(f"\n== {t}")


def te_and_cl():
    section("Transfer-Encoding / Content-Length disguises (smuggled GET must not be served)")
    for v in [b"xchunked", b"chunked, identity", b"identity, chunked", b"identity",
              b"chunked\x00", b"chunk", b" chunked", b"chunked;q=1", b"gzip, chunked"]:
        check(f"TE: {v!r} + CL + smuggled GET",
              b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: 4\r\n"
              b"Transfer-Encoding: " + v + b"\r\n\r\n0\r\n\r\n" + SMUGGLE, ERR_OR_CLOSE)
    check("TE: chunked (valid) then pipelined hello",
          b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
          b"5\r\nhello\r\n0\r\n\r\n" + get(), {200})
    check("TE: CHUNKED uppercase valid",
          b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: CHUNKED\r\n\r\n0\r\n\r\n",
          {200, 400})
    for v in [b"+5", b"0x5", b"-1", b"5, 5", b"1e1", b"\xd9\xa5", b"", b"5 5", b"0005x"]:
        check(f"CL: {v!r} + smuggled GET",
              b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: " + v +
              b"\r\n\r\nhello" + SMUGGLE, ERR_OR_CLOSE)
    check("CL: 10000 digits", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: "
          + b"9" * 10000 + b"\r\n\r\n", {400, 413, 431})
    check("CL: 0 is fine", get(hdrs="Host: x\r\nContent-Length: 0\r\n"), {200})
    check("CL: valid body then pipelined hello",
          b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhello" + get(), {200})


def chunk_abuse():
    section("Chunked-encoding abuse")
    head = b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n"
    for name, body in [
        ("chunk size overflow FFFFFFFFFFFFFFFFFFFF", b"FFFFFFFFFFFFFFFFFFFF\r\nx\r\n0\r\n\r\n"),
        ("chunk size 0x5", b"0x5\r\nhello\r\n0\r\n\r\n"),
        ("chunk size -1", b"-1\r\nhello\r\n0\r\n\r\n"),
        ("chunk size leading space", b" 5\r\nhello\r\n0\r\n\r\n"),
        ("empty chunk size line", b"\r\nhello\r\n0\r\n\r\n"),
        ("chunk data longer than size", b"2\r\nhello\r\n0\r\n\r\n"),
        ("huge chunk extension", b"5;" + b"a=b;" * 5000 + b"\r\nhello\r\n0\r\n\r\n"),
        ("1 GiB single chunk claim", b"40000000\r\nxx"),
        ("bare LF in chunk framing", b"5\nhello\n0\n\n"),
    ]:
        check(f"chunk: {name}", head + body + SMUGGLE, {0, 400, 413, 431, 408}, wait=5)
    check("chunk: missing terminating 0 chunk -> 408 not hang", head + b"5\r\nhello\r\n",
          {408, 400, 0}, wait=40)
    check("chunk: trailer with CL smuggle attempt",
          head + b"0\r\nContent-Length: 50\r\n\r\n" + get(), {200, 400})


def request_line_abuse():
    section("Request line / header oddities")
    cases = [
        ("lowercase method", b"get /helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", {400, 501}),
        ("two spaces in request line", b"GET  /helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", ERR),
        ("tab separators", b"GET\t/helloworld.html\tHTTP/1.1\r\nHost: x\r\n\r\n", ERR),
        ("no version", b"GET /helloworld.html\r\nHost: x\r\n\r\n", ERR),
        ("target without leading slash", b"GET helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", ERR),
        ("absolute-URI target", b"GET http://x/helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", {200, 400}),
        ("asterisk target", b"GET * HTTP/1.1\r\nHost: x\r\n\r\n", ERR),
        ("OPTIONS *", b"OPTIONS * HTTP/1.1\r\nHost: x\r\n\r\n", {501, 400}),
        ("CONNECT", b"CONNECT x:443 HTTP/1.1\r\nHost: x\r\n\r\n", {501, 400}),
        ("HEAD", b"HEAD /helloworld.html HTTP/1.1\r\nHost: x\r\n\r\n", {200, 501}),
        ("HTTP/2.0", get(ver="HTTP/2.0"), {505}),
        ("HTTP/1.11", get(ver="HTTP/1.11"), {400, 505}),
        ("HTTP/0.9", get(ver="HTTP/0.9"), {400, 505}),
        ("lowercase http/1.1", get(ver="http/1.1"), {400, 505}),
        ("HTTP/1.0 no Host", b"GET /helloworld.html HTTP/1.0\r\n\r\n", {200, 400}),
        ("leading blank line before request", b"\r\n" + get(), {200, 400}),
        ("obs-fold header", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX-A: b\r\n c\r\n\r\n", ERR),
        ("header without colon", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nNoColon\r\n\r\n", ERR),
        ("empty header name", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\n: v\r\n\r\n", ERR),
        ("space in header name", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX A: v\r\n\r\n", ERR),
        ("NUL in header value", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX-A: a\x00b\r\n\r\n", {200, 400}),
        ("bare CR in header value", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX-A: a\rb\r\n\r\n", ERR),
        ("non-ASCII header bytes", b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nX-A: \xff\xfe\r\n\r\n", {200, 400}),
        ("binary garbage", bytes(range(256)) * 4 + b"\r\n\r\n", {400, 431, 414}),
        ("TLS ClientHello-ish bytes", b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03" + b"\x00" * 64, {0, 400, 408}),
        ("CRLF injection via target", b"GET /x%0d%0aSet-Cookie:%20a=b HTTP/1.1\r\nHost: x\r\n\r\n", {400, 404}),
        ("Host with CRLF-encoded junk", b"GET /helloworld.html HTTP/1.1\r\nHost: x%0d%0aX: y\r\n\r\n", {200, 400}),
    ]
    for name, raw, ok in cases:
        check(name, raw, ok, wait=4)
    data = talk(b"GET /x%0d%0aSet-Cookie:%20a=b HTTP/1.1\r\nHost: x\r\n\r\n")
    inj = b"\r\nSet-Cookie" in data
    print(f"  {'LANDED' if inj else 'PASS  '} response splitting: injected Set-Cookie header in reply? {inj}")
    if inj:
        landed.append("response splitting")


def path_abuse():
    section("Exotic path traversal / path tricks (must never return file contents)")
    leak_markers = [b"root:x:", b"def handle_connection", b"HEADER_TIMEOUT"]
    paths = [
        "/..\\..\\etc\\passwd", "/%5c..%5c..%5cetc/passwd", "/..;/..;/etc/passwd",
        "/%2e%2e/%2e%2e/etc/passwd", "/..%2f..%2fetc/passwd", "/%2e%2e%5c%2e%2e%5cetc/passwd",
        "/%c0%ae%c0%ae/%c0%ae%c0%ae/etc/passwd", "/%e0%80%ae%e0%80%ae/etc/passwd",
        "//etc/passwd", "/%2fetc/passwd", "/./././../../etc/passwd",
        "/evidence/../server.py", "/./server.py", "//server.py", "/%73erver.py",
        "/server.py%20", "/server.py.", "/server.py/", "/server.py?x=1", "/server.py#a",
        "/.git/config", "/%2egit/config", "/redteam/../.gitignore",
        "/helloworld.html%00.txt", "/%00", "/%", "/%zz", "/%2", "/helloworld.html/..",
        "/" + "../" * 200 + "etc/passwd", "/" + "%2e%2e%2f" * 100 + "etc/passwd",
        "/%252e%252e%252f%252e%252e%252fetc/passwd", "/%25252e%25252e/etc/passwd",
        "/‥/etc/passwd".encode("utf-8").decode("latin-1"),
    ]
    for p in paths:
        raw = b"GET " + p.encode("latin-1", "replace") + b" HTTP/1.1\r\nHost: x\r\n\r\n"
        data = talk(raw)
        cs = codes(data)
        for c in cs:
            seen_codes[c] = seen_codes.get(c, 0) + 1
        leaked = any(m in data for m in leak_markers)
        bad = leaked or 500 in cs or (cs and cs[0] == 200 and not p.startswith("/helloworld"))
        if bad:
            landed.append("path " + p)
        print(f"  {'LANDED' if bad else 'PASS  '} {p[:50]!r:55s} -> {cs or 'closed'}{' LEAK' if leaked else ''}")


def pipelining():
    section("Pipelining / delivery patterns")
    n = 200
    data = talk(get(hdrs="Host: x\r\nConnection: keep-alive\r\n") * n, wait=8)
    got = codes(data).count(200)
    print(f"  {'PASS  ' if got == n or got >= 1 else 'LANDED'} {n} pipelined GETs in one send -> {got} x 200 (server may cap; must not crash)")
    req = get()
    data = talk(b"", chunks=[req[i:i + 1] for i in range(len(req))], delay=0.01, wait=5)
    ok = codes(data) == [200]
    print(f"  {'PASS  ' if ok else 'LANDED'} valid request delivered 1 byte at a time -> {codes(data)}")
    if not ok:
        landed.append("byte-at-a-time")
    split = b"GET /helloworld.html HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\n\r\nhel"
    data = talk(b"", chunks=[split, b"lo" + get()], delay=0.3, wait=5)
    ok = codes(data) == [200, 200]
    print(f"  {'PASS  ' if ok else 'LANDED'} body split across segments, then pipelined GET -> {codes(data)}")
    if not ok:
        landed.append("split body")
    data = talk(b"", chunks=[b"GET /helloworld.html HTTP/1.1\r", b"\nHost: x\r\n\r\n"], delay=0.3, wait=5)
    print(f"  PASS   CRLF split across segments -> {codes(data)} (expected [200])")
    if codes(data) != [200]:
        landed.append("split CRLF")


def flood_and_slow():
    section("Connection flood (must not lock out a normal client)")
    held = []
    for _ in range(600):
        try:
            held.append(socket.create_connection((HOST, PORT), timeout=3))
        except OSError:
            break
    print(f"  opened {len(held)} idle connections")
    time.sleep(1)
    t = time.time()
    data = talk(get(), wait=5)
    ok = codes(data) == [200]
    print(f"  {'PASS  ' if ok else 'LANDED'} normal client during idle flood -> {codes(data) or 'refused/closed'} in {time.time() - t:.2f}s")
    if not ok:
        landed.append("idle connection flood locks out clients")
    for s in held:
        s.close()
    time.sleep(1)
    data = talk(get())
    print(f"  {'PASS  ' if codes(data) == [200] else 'LANDED'} normal client after flood closes -> {codes(data)}")

    section("Slow reader (requests 5 MB file, never reads) x 60")
    socks = []
    for _ in range(60):
        s = socket.create_connection((HOST, PORT), timeout=3)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
        s.sendall(get("/english_words.txt"))
        socks.append(s)
    time.sleep(2)
    data = talk(get(), wait=5)
    ok = codes(data) == [200]
    print(f"  {'PASS  ' if ok else 'LANDED'} normal client while 60 stalled readers -> {codes(data)}")
    if not ok:
        landed.append("slow readers lock out clients")
    print("  (leaving stalled readers open; check thread count with the commands in the summary)")
    return socks


def main():
    print(f"Target {HOST}:{PORT}")
    te_and_cl()
    chunk_abuse()
    request_line_abuse()
    path_abuse()
    pipelining()
    socks = flood_and_slow()
    section("Status codes observed in this run")
    for c in sorted(seen_codes):
        print(f"  {c}: {seen_codes[c]}")
    print("\nLANDED:" if landed else "\nNothing landed.")
    for l in landed:
        print("  -", l)
    time.sleep(1)
    for s in socks:
        s.close()


if __name__ == "__main__":
    main()
