# Red team notes

Five scripts, one per family. Start the server, then run any of them, ex:

```
python3 server.py 8080
python3 redteam/attack_framing.py localhost 8080
```

`attack_resource_exhaustion.py` takes about 20 seconds because it waits on timeouts. `attack_robustness.py` takes a few minutes. `util.py` is just the shared send/print helper.

## What each script does and what the server did

**attack_framing.py** (smuggling and desync)
Sends conflicting Content-Length headers, Content-Length plus Transfer-Encoding, bare LF line endings, a body longer than declared with a GET pipelined behind it, bad chunk sizes, bad chunk terminators, and a space before a header colon.
Server: 400 on every ambiguous one and the connection closes. For the over-long body the extra bytes get read as the next request line, which is garbage, so it gets 501 and a close. The pipelined GET is never served.

**attack_path_traversal.py**
Literal `../`, `%2e%2e%2f`, double-encoded (`%252e%252e%252f`), null byte, dotfile, the server's own source, and a bare directory.
Server: 403 for the literal and percent-encoded escapes, the double-encoded attempt (a second, detection-only decode shows it would reveal `../../etc/passwd`, so it's rejected instead of resolving to an inert literal filename), the null byte, the dotfile, and the own-source request; 404 only for the bare directory.

**attack_protocol_edges.py**
Missing Host, duplicate Host, `HTTP/9.9`, and a POST with a body and a GET pipelined behind it.
Server: 400, 400, 505, and 501 with the connection closed (so the body bytes can't turn into a request).

**attack_resource_exhaustion.py**
Slowloris (5 connections trickling headers) while a normal client keeps requesting, a short body, a 10,000 character URL, one huge header, 500 headers, and a 999999999999 Content-Length.
Server: normal client answered in about 0.01s during Slowloris, the slow connections get cut, then 408, 414, 431, 431, 413.

**attack_robustness.py** (the harder one, about 120 cases)
- Transfer-Encoding tricks: `xchunked`, `chunked, identity`, `chunked\x00`, and others, each with a Content-Length and a smuggled GET behind it.
- Content-Length tricks: `+5`, `0x5`, `-1`, `5, 5`, `1e1`, unicode digits, empty, 10,000 digits.
- Chunk abuse: size overflow, `0x5`, negative size, leading space, giant extensions, a 1 GiB chunk claim, bare LF framing, no final `0` chunk.
- Request line and header oddities: tabs, double spaces, lowercase method, `OPTIONS *`, `CONNECT`, bad versions, obs-fold, NUL and bare CR in values, binary junk, CRLF injected through the URL.
- Path tricks: backslashes, `..;/`, overlong UTF-8, `//etc/passwd`, 200 levels of `../`, triple encoding, trailing dots and slashes on `server.py`.
- Delivery: 200 pipelined requests in one send, a request sent one byte at a time, a body split across segments, CRLF split across segments.
- A flood of 600 idle connections, then a normal request.
- 60 clients that ask for the 5 MB file and never read it.

Server: everything now gets 400, 403, 404, 408, 413, 431, 501 or 505 as appropriate, or a clean close. No 500s and no leaked files. A symlink inside the served directory that points outside it also gets 403 (checked by hand, not in the script).

## What it caught and what I changed in server.py

The first run of `attack_robustness.py` landed three attacks.

1. **Header name with a space.** `X A: v` came back 200. I only rejected whitespace before the colon, so a name with a space inside slipped through. Header names are now checked against the allowed token characters and get a 400.
2. **Chunk size with a leading space.** `" 5"` was accepted because I called `.strip()` on the size field. A stricter proxy in front would parse that differently, which is how smuggling starts. Sizes are now plain hex only, 400 otherwise.
3. **Idle connection flood.** 600 idle sockets filled the 500 connection cap and every new client was dropped, so one attacker locked everyone out. At the cap the server now closes the oldest connection that never finished a request and lets the new one in. The thread count still never goes over 500.

One more "landing" in that first run was a bug in my script, not the server. A valid chunked body followed by a GET really is two requests. I fixed the script.

After the fixes the new script, the published harness and the four older scripts all came back clean, and the normal client kept getting 200s while they ran. The stalled readers get dropped by the timeout within about 40 seconds and the thread count goes back to 1.

## Second pass: a code review surfaced five more gaps

Not things any attack script caught -- found by reading the code, not by running against it -- so I'm recording them here rather than claiming an attack "landed."

1. **`self_paths` only listed `server.py`/`client.py`.** `redteam/*.py` and `NOTES.md` itself would have been served if they happened to sit in the served directory, since nothing named them. Replaced with `collect_source_paths()`, which walks the served tree at startup and blocks every `.py`/`.md` file, not just two hardcoded names.
2. **`_check_bare_terminators` rescanned the whole header buffer on every `recv()`.** A client trickling up to the 64 KiB header cap one byte at a time made that a pure-Python O(n^2) scan held under the GIL -- a cheap way to burn CPU for everyone, not just the attacker's own connection. Now it tracks how much of the buffer it already checked and only scans the new suffix.
3. **`sendall()` borrowed whatever timeout was left on the socket from the last `recv()`.** That's fine by accident for a short response, but a legitimately slow download of `english_words.txt` could get cut off by a read-side deadline it has nothing to do with. Added a separate `WRITE_TIMEOUT` so writes have their own, intentional budget instead of an inherited one.
4. **HTTP/1.0 defaulted to keep-alive.** The spec says 1.0 should default to `close` unless the client opts in with `Connection: keep-alive`; we treated 1.0 and 1.1 the same, so a plain 1.0 client would sit on the connection until `IDLE_TIMEOUT` instead of getting a prompt close.
5. **Eviction at the connection cap can shut a legitimate client's first request, not just an attacker's.** This is a real tradeoff, not a bug -- the alternative is refusing new clients outright once the cap is hit, which is worse. Left as is, documented in a comment next to `evict_one()`.
6. **A double-encoded traversal attempt (`%252e%252e%252f...`) decoded once resolves to a literal, nonexistent filename and would otherwise 404** -- technically safe (it never escapes the served directory), but silently swallowing an attack as a 404 instead of naming it is worse than flagging it. `safe_resolve_path` now does one extra, detection-only decode: if that second decode would reveal `..`/`\\`/an extra `/` that the first decode didn't have, it's rejected as a 403 outright instead of falling through to "file not found."

I also fixed two scripts that were checking less than they looked like they were:

- **`attack_resource_exhaustion.py`'s `slowloris()`** trickled for ~96s (48 bytes x 2s) but the server's `HEADER_TIMEOUT` is 15s, so the script was always sending into an already-closed socket by the time it got around to `recv()` -- it recorded the resulting `ConnectionResetError`, never the actual `408`. Now it polls with `select()` after each byte so it reads the 408 the moment the server sends it.
- **`attack_robustness.py` had two assertions that couldn't fail.** The 200-pipelined-GETs check accepted `got >= 1`, i.e. passed even if 199 of 200 were silently dropped; tightened to require all 200. The CRLF-split-across-segments case printed `PASS` unconditionally before it had looked at the result at all; it now checks first.

## Third pass: one real false-positive bug, one memory bound, one code-vs-handout mismatch

1. **A bare `\n` inside the body could get rejected as a bare LF in the request.** `_check_bare_terminators` scanned the *entire* buffered bytearray, and when the headers' `\r\n\r\n` terminator and the start of the body arrived in the same `recv()`, that scan ran past the terminator and into the body -- so `Content-Length: 11` with a body of `hello\nworld` got a wrong `400` if it arrived in one segment, and the correct `200` if the body happened to arrive in a later segment. Behavior that depends on where the TCP segment boundary happens to fall is exactly the bug class this lab is about. Fixed by capping the scan at the end of the found `\r\n\r\n` (or the whole buffer if it hasn't arrived yet) instead of the whole buffer regardless.
2. **`send_file_response` read the whole file into memory per connection.** `f.read()` on `english_words.txt` (~5 MB) means N stalled connections hold N full copies in memory -- 500 stalled readers is on the order of 2.5 GB. Rewrote it to stream in 64 KiB chunks instead, so memory per connection is bounded by the chunk size, not the file size.
3. **Null byte now returns 403, not 400.** The handout's path-safety paragraph groups a null byte with traversal and encoding tricks and expects it handled the same way as those (403); the status-code table's 400 is for malformed framing, not path-safety rejections specifically. Changed for consistency with the double-encoded-path check above, which is also a 403.
