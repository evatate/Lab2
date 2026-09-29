# Postmortem: bare LF/CR line endings degraded to a 15-second timeout instead of an immediate 400

## The attack

```
GET /helloworld.html HTTP/1.1\n
Host: localhost\n
\n
```

(`attack_framing.py`'s `bare_line_endings` case — every line terminated with
a lone `\n` instead of `\r\n`.) Sent as one `sendall()` over a fresh raw
socket, then the client waited on `recv()` with a 5-second timeout.

## What happened vs. what I expected

**Expected:** RFC 9112 requires every line to end in CRLF; a bare LF (or a
bare CR not followed by LF) is illegal framing, so I expected an immediate
`400 Bad Request`.

**Observed (pre-fix):** nothing came back within the 5-second window — the
client's `recv()` raised `socket.timeout` and printed `<TIMEOUT>`. The
server process was confirmed still alive (`ps` still showed the PID); it
just never answered this particular request in any observable time window.

## Root cause

The first version of `read_head()` located the end of the request head with
a single call:

```python
raw = reader.read_until(b"\r\n\r\n", MAX_HEADER_BLOCK_BYTES, deadline, ...)
```

`read_until` has exactly three ways to return control: find the delimiter,
exceed `MAX_HEADER_BLOCK_BYTES` (64 KiB), or let the cumulative
`HEADER_TIMEOUT` (15 s) deadline elapse inside `_fill()`. A request that
uses `\n` alone never produces the byte sequence `b"\r\n\r\n"` — the buffer
just sits there containing `"GET /helloworld.html HTTP/1.1\nHost:
localhost\n\n"` (47 bytes, nowhere near the 64 KiB cap) waiting for bytes
that are never going to arrive, because the client already sent everything
it was going to send.

So there were only two possible resolutions, and neither was the `400` I
wanted: the connection would eventually die 15 seconds later with a generic
`408 Request Timeout`, or — if the client had also kept its socket open
indefinitely without ever sending the terminator — it genuinely would sit
open for the full `HEADER_TIMEOUT` every single time. The parser had no
representation of "this line ending is illegal" at all; it only understood
"the terminator hasn't shown up yet," which is indistinguishable, from
inside `read_until`, from an ordinary slow client that just hasn't finished
typing.

That matters for two concrete reasons, not just tidiness:

1. **It's a free resource-tie-up primitive.** One malformed line, sent once,
   occupies a connection slot (and a thread) for a full 15 real seconds
   before the server notices anything is wrong — cheaper for an attacker
   than an honest Slowloris trickle, which at least has to keep sending
   bytes to stay alive.
2. **It erases the signal a smuggling defense needs.** If this server sat
   behind a front-end proxy that *does* treat bare LF as a valid line
   terminator (several real servers historically have, for leniency), the
   two disagree about where a line ends. That disagreement is the
   precondition for a desync, and a backend that can't even distinguish
   "illegal framing" from "slow client" has no fast, explicit way to reject
   the ambiguous case before it's exploited.

## The fix

Added `_check_bare_terminators()`, run against the whole accumulated buffer
every time new bytes arrive, *before* checking for the `b"\r\n\r\n"`
delimiter:

```python
def _check_bare_terminators(buf):
    n = len(buf)
    for i, byte in enumerate(buf):
        if byte == 0x0A:  # \n
            if i == 0 or buf[i - 1] != 0x0D:
                raise HttpError(400, "bare LF in request")
        elif byte == 0x0D:  # \r
            if i < n - 1 and buf[i + 1] != 0x0A:
                raise HttpError(400, "bare CR in request")
```

(The `i < n - 1` guard on the CR case matters: a `\r` that is the very last
byte *currently* buffered might still be legitimately completed into `\r\n`
by the next `recv()` — flagging it immediately would misfire on a perfectly
normal request split across two TCP segments right at the line boundary.)

**Confirmed fixed** — re-running the identical bytes against the patched
server produces, immediately (`server.log`):

```
[14:48:02] 127.0.0.1:50399 400 while reading headers: bare LF in request
```

and the client receives `HTTP/1.1 400 Bad Request` in the same call instead
of timing out.

## One defense, and what breaks without it

The single-`Content-Length`-and-`Transfer-Encoding`-can't-coexist check in
`parse_headers()` (`server.py`) is the one that matters most: remove it, and
the "conflicting Content-Length + Transfer-Encoding" request in
`attack_framing.py` would have the server pick one framing header while a
downstream proxy or the client's own idea of the message picks the other —
the classic CL.TE/TE.CL request-smuggling desync that lets an attacker plant
bytes that get parsed as the start of a request the real client never sent.
