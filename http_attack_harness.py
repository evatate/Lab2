#!/usr/bin/env python3
"""
# ==============================================================================
# File Name:     http_attack_harness.py
# Author:        Mostly Claude Code Opus 4.8, edited by Tim Pierson
# Course:        CS60: Computer Networks
# Assignment:    Lab 2: Application Layer - Hardened Web Server Lb
# Date:          September 2026
#
# Description:   Tries various attacks against a web server.
#
# ==============================================================================

Point this at YOUR web server while you harden it. For each attack it explains
what it sends and why a fragile server fails, then reports whether your server
held up. It does NOT tell you how to fix anything -- that's the assignment.

Run:

    python3 http_attack_harness.py [host] [port] [known_path]
    defaults:                       127.0.0.1  8080  /helloworld.html

`known_path` must be a file your server serves successfully (200). The lab
ships helloworld.html; put it in your server's directory and you're set.

Two severities:
  [MUST]   a real vulnerability -- crash, hang, desync, data leak, or losing
           all other clients during an attack. If any MUST fails, you are not
           done. The script's exit code is nonzero while any MUST fails.
  [SHOULD] status-code discipline the rubric expects (e.g. 413 for an oversized
           body). Not a security hole, but it costs points. Shown as warnings.

This is the PUBLISHED suite: it shows you the categories you'll be graded on.
Grading also uses a hidden suite with more variations, so make your server
robust in general -- don't just tune it until this script is green.

"""

import socket
import sys
import threading
import time

HOST = sys.argv[1] if len(sys.argv) > 1 else "127.0.0.1"
PORT = int(sys.argv[2]) if len(sys.argv) > 2 else 8080
KNOWN = (sys.argv[3] if len(sys.argv) > 3 else "/helloworld.html").encode()
MISSING = b"/__does_not_exist_" + str(int(time.time())).encode() + b".html"

must_fail = 0
should_gap = 0

def hdr(title):
    print("\n" + "=" * 70 + f"\n{title}\n" + "=" * 70)

def report(sev, name, ok, explain, got=""):
    global must_fail, should_gap
    mark = "PASS" if ok else ("FAIL" if sev == "MUST" else "WARN")
    tag = "" if ok else f"[{sev}] "
    print(f"  {mark:4} {tag}{name}")
    if not ok:
        print(f"       -> {explain}")
        if got:
            print(f"       -> your server: {got}")
        if sev == "MUST":
            must_fail += 1
        else:
            should_gap += 1

def probe(payload, timeout=4.0, keep_reading_secs=0.0):
    """Send raw bytes; collect the response. Returns dict with keys:
    lines (list of status lines), raw (bytes), timed_out (bool),
    closed (bool), error (str|None)."""
    out = {"lines": [], "raw": b"", "timed_out": False, "closed": False, "error": None}
    try:
        s = socket.create_connection((HOST, PORT), timeout)
    except OSError as e:
        out["error"] = f"could not connect ({e}); is your server running on {HOST}:{PORT}?"
        return out
    s.settimeout(timeout)
    try:
        s.sendall(payload)
    except OSError:
        pass  # server may have closed early after rejecting; still try to read
    data = b""
    deadline = time.time() + (keep_reading_secs or timeout)
    try:
        while time.time() < deadline:
            chunk = s.recv(65536)
            if not chunk:
                out["closed"] = True
                break
            data += chunk
            if not keep_reading_secs and b"\r\n\r\n" in data and data.count(b"HTTP/1.") >= 1:
                # got at least one full response head; brief extra peek for pipelined extras
                s.settimeout(0.4)
                try:
                    while True:
                        more = s.recv(65536)
                        if not more:
                            out["closed"] = True
                            break
                        data += more
                except socket.timeout:
                    pass
                break
    except socket.timeout:
        out["timed_out"] = True
    except OSError:
        out["closed"] = True
    finally:
        s.close()
    out["raw"] = data
    out["lines"] = [ln for ln in data.split(b"\r\n") if ln.startswith(b"HTTP/1.")]
    return out

def status_code(resp):
    if not resp["lines"]:
        return None
    parts = resp["lines"][0].split(b" ")
    return int(parts[1]) if len(parts) > 1 and parts[1].isdigit() else None


# ----------------------------------------------------------------------------
print(__doc__.split("\n\n")[0])
print(f"\nTarget: {HOST}:{PORT}   known-good path: {KNOWN.decode()}")

# --- sanity: can we talk to the server at all? ---
base = probe(b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
if base["error"]:
    print("\nCannot reach your server: " + base["error"])
    sys.exit(2)
if status_code(base) != 200:
    print(f"\nWARNING: GET {KNOWN.decode()} did not return 200 (got {status_code(base)}).")
    print("Pass a path your server actually serves as the 3rd argument, e.g.:")
    print(f"    python3 {sys.argv[0]} {HOST} {PORT} /index.html")
    print("Continuing anyway, but some checks assume a served file.\n")


hdr("Family 0: baseline (sanity, not an attack)")
report("MUST", "serves a known file (200)", status_code(base) == 200,
       "The harness needs a working GET to test against.",
       f"got {status_code(base)}")
miss = probe(b"GET " + MISSING + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
report("SHOULD", "404 for a missing file", status_code(miss) == 404,
       "A well-formed request for a file that isn't there should be 404.",
       f"got {status_code(miss)}")


hdr("Family 1: framing, smuggling & desync")
print("A keep-alive connection carries requests back-to-back on one byte stream.")
print("The server must measure each body exactly, or an attacker can blur the")
print("boundary between requests. Ambiguous framing must be refused, not guessed.\n")

r = probe(b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\n"
          b"Content-Length: 5\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n")
report("MUST", "Content-Length + Transfer-Encoding: no hang/crash", not r["timed_out"],
       "Sending both length headers is the classic smuggling probe; your server "
       "hung instead of responding.", "timed out waiting for a response")
report("SHOULD", "...answered with 400", status_code(r) == 400,
       "Contradictory framing should be rejected as 400 Bad Request.",
       f"got {status_code(r)}")

r = probe(b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\n"
          b"Content-Length: 5\r\nContent-Length: 6\r\n\r\nhello")
report("SHOULD", "two conflicting Content-Length -> 400", status_code(r) == 400,
       "Disagreeing Content-Length headers are unresolvable and should be 400.",
       f"got {status_code(r)}")

r = probe(b"GET " + KNOWN + b" HTTP/1.1\nHost: x\n\n")
report("MUST", "bare-LF line endings: no hang/crash", not r["timed_out"] and bool(r["lines"] or r["closed"]),
       "Lines ending in LF without CR are malformed; your server hung on them.",
       "timed out")

# desync: a GET whose body IS a smuggled request, pipelined before a real one.
smuggled = b"GET /SMUGGLED-CANARY HTTP/1.1\r\nHost: x\r\n\r\n"
trailing = b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n"
payload = (b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nContent-Length: "
           + str(len(smuggled)).encode() + b"\r\n\r\n" + smuggled + trailing)
r = probe(payload, timeout=6)
n_resp = len(r["lines"])
# Safe: 1 response (declined+closed) or 2 (consumed body, served both real requests).
# Vulnerable: 3+ (the smuggled request got parsed and served on its own).
desync_safe = (not r["timed_out"]) and n_resp <= 2
report("MUST", "no desync from a smuggled body", desync_safe,
       "Your server appears to have parsed the request hidden in the body and "
       "served it as a separate request -- that's a desync. It must either "
       "consume the declared body or close the connection.",
       f"{n_resp} responses came back (expected 1 or 2)" if not r["timed_out"] else "hung")


hdr("Family 2: slow clients & resource exhaustion")
print("These starve a server's connection capacity rather than its bandwidth.")
print("The key property: one slow or abusive client must not stall everyone else.\n")

# Slowloris: an incomplete request that never sends the final blank line, held
# open in the background while we time how long a NORMAL client waits.
slow_result = {}
def slowloris_bg():
    try:
        s = socket.create_connection((HOST, PORT), 10)
        s.sendall(b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\n")  # never finishes
        s.settimeout(25)
        data = b""
        t0 = time.time()
        try:
            while time.time() - t0 < 25:
                c = s.recv(4096)
                if not c:
                    break
                data += c
                if b"\r\n\r\n" in data:
                    break
        except (socket.timeout, OSError):
            pass
        slow_result["raw"] = data
        slow_result["cut_after"] = time.time() - t0
        s.close()
    except OSError as e:
        slow_result["error"] = str(e)

t = threading.Thread(target=slowloris_bg, daemon=True)
t.start()
time.sleep(1.0)  # let the slow connection get established and stall

t0 = time.time()
normal = probe(b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n", timeout=6)
served_dt = time.time() - t0
report("MUST", "other clients still served DURING a slow attack",
       status_code(normal) == 200 and served_dt < 3.0,
       "A normal request stalled while one slow client was mid-attack -- your "
       "concurrency model lets a single slow connection block everyone.",
       f"normal client took {served_dt:.1f}s / status {status_code(normal)}")

print("  ...  waiting up to ~20s to see if your server cuts the slow client")
t.join(timeout=22)
cut = slow_result.get("cut_after")
raw = slow_result.get("raw", b"")
got_408 = b"408" in raw
cut_ok = (cut is not None and cut < 20) or got_408 or (raw == b"" and cut is not None and cut < 20)
report("SHOULD", "slow/incomplete request eventually cut (ideally 408)", got_408,
       "The rubric expects a stalled request to be timed out with 408. Your "
       "server " + ("never cut it within 20s." if cut is None or cut >= 20
                    else "closed it without a 408 status."),
       f"cut after {cut:.1f}s, saw {'408' if got_408 else 'no 408'}" if cut is not None
       else "not cut within 20s")

# oversized declared body
big = b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 5000000\r\n\r\n" + b"A" * 5000000
r = probe(big, timeout=8)
sc = status_code(r)
report("MUST", "oversized body: server stays responsive", not r["timed_out"] and (bool(r["lines"]) or r["closed"]),
       "A 5 MB body made your server hang or die instead of bounding the input.",
       "hung / no response")
report("SHOULD", "...answered 413 (Content Too Large)", sc == 413,
       "Bodies over your limit should be refused with 413, not served (200) or "
       "silently accepted.", f"got {sc}")

# over-long URI
r = probe(b"GET /" + b"A" * 9000 + b" HTTP/1.1\r\nHost: x\r\n\r\n")
report("SHOULD", "over-long request line -> 414", status_code(r) == 414,
       "A giant request target should be 414 URI Too Long.", f"got {status_code(r)}")

# too many headers
many = b"GET " + KNOWN + b" HTTP/1.1\r\nHost: x\r\n" + b"".join(
    b"X-Pad-%d: y\r\n" % i for i in range(300)) + b"\r\n"
r = probe(many)
report("SHOULD", "excessive headers -> 431", status_code(r) == 431,
       "Too many/too-large headers should be 431 Request Header Fields Too Large.",
       f"got {status_code(r)}")


hdr("Family 3: path traversal")
print("If you map request paths to files, an attacker will try to climb out of")
print("the served directory to read files you never meant to expose.\n")

for label, path in [("../ traversal", b"/../../../../etc/passwd"),
                    ("encoded %2e%2e traversal", b"/%2e%2e/%2e%2e/%2e%2e/etc/passwd")]:
    r = probe(b"GET " + path + b" HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
    leaked = b"root:" in r["raw"] and status_code(r) == 200
    report("MUST", f"{label}: no file leaked", not leaked,
           "Your server returned the contents of a file OUTSIDE the served "
           "directory. This is the vulnerability -- the path escaped your docroot.",
           "leaked /etc/passwd contents")
    report("SHOULD", f"{label}: rejected (404/403)", status_code(r) in (404, 403),
           "A traversal attempt should be refused with 404 (or 403), not 200 or 400.",
           f"got {status_code(r)}")


hdr("Family 4: method & version")
r = probe(b"POST " + KNOWN + b" HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n")
report("SHOULD", "unsupported method -> 501", status_code(r) == 501,
       "A method you don't implement should be 501 Not Implemented.", f"got {status_code(r)}")
r = probe(b"GET " + KNOWN + b" HTTP/2.0\r\nHost: x\r\n\r\n")
report("SHOULD", "unsupported version -> 505", status_code(r) == 505,
       "A well-formed but unsupported version should be 505.", f"got {status_code(r)}")


# ----------------------------------------------------------------------------
hdr("Summary")
if must_fail == 0 and should_gap == 0:
    print("  All checks passed. Your server survives the published suite cleanly.")
    print("  Remember: the TA's grading suite has more variations -- robustness,")
    print("  not tuning your server to this script, is what earns the points.")
elif must_fail == 0:
    print(f"  No MUST failures -- no outright vulnerabilities found. Good.")
    print(f"  {should_gap} SHOULD gap(s): status-code discipline the rubric expects.")
    print("  These aren't security holes but they do cost points; tighten them up.")
else:
    print(f"  {must_fail} MUST failure(s): real problems (leak / hang / desync / lost")
    print("  concurrency). You are not done until these are green.")
    if should_gap:
        print(f"  Also {should_gap} SHOULD gap(s) in status-code discipline.")
print()
sys.exit(1 if must_fail else 0)
