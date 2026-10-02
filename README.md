# CS60 Lab 2 — Hardened Web Server Lab

## Running it

```
python3 server.py <port>
```

Serves files from the directory the server is started in. No other
arguments or configuration.

```
python3 client.py <server_host> <server_port> <path>
```

Prints the raw response (status line, headers, body) to stdout.

Put `helloworld.html` and `english_words.txt` alongside `server.py` before
starting it (both are already in this directory; `english_words.txt` is
built from `/usr/share/dict/words` repeated twice, ~5 MB, to force a
multi-packet transfer).

## Design

- **Concurrency:** thread-per-connection, bounded by a semaphore
  (`MAX_CONNECTIONS = 500` in `server.py`). A connection beyond that cap is
  closed immediately at accept time rather than spawning another thread, so
  a connection flood can't grow the thread count without bound.
- **Timeouts are cumulative, not per-`recv()`.** A client trickling one
  byte every couple of seconds never trips a single `recv()` timeout, so
  the server tracks an absolute deadline for finishing the headers
  (`HEADER_TIMEOUT`), for finishing a declared body (`BODY_TIMEOUT`), and
  for the idle wait before the next request on a keep-alive connection
  (`IDLE_TIMEOUT`). See `redteam/attack_resource_exhaustion.py` for the
  Slowloris test this defeats.
- **Framing is fail-closed.** Any ambiguity in how a request's body is
  measured — conflicting `Content-Length` headers, `Content-Length` next to
  `Transfer-Encoding`, bad chunk syntax, bare CR/LF line endings, whitespace
  before a header colon — gets a `400` and the connection is closed
  outright. The lab explicitly allows closing the connection on anything
  declined; doing so means the server never has to guess where the next
  request actually starts on a connection it doesn't trust.
- **Every request's body is consumed before moving on, regardless of
  method.** A `POST` (or anything other than `GET`) still gets its declared
  body read off the socket before the `501` is sent, so a rejected request
  never leaves body bytes sitting on the wire to be misread as the start of
  the next request.
- **Path safety:** the request target is percent-decoded exactly once (an
  extra layer of encoding just fails to resolve to a real file, which is
  the safe outcome), resolved with `os.path.realpath`, and checked that it
  is still inside the served directory. Dotfiles, the server's own source,
  and directories are all explicitly `403`.

## Status code choices worth noting

- A bare `GET /` (no file named) returns `404`, not `403` — there's no
  default index file, so "nothing was asked for" is `Not Found` rather than
  `Forbidden`. A path that *resolves outside* the served directory, or to a
  dotfile / the server's own source, is `403`.
- Requesting a directory that exists inside the served tree (there are none
  by default, but the check is there) is `403` rather than a listing.

## Structure

```
server.py                          hardened HTTP/1.1 server
client.py                          command-line HTTP client
helloworld.html, english_words.txt test files
http_attack_harness.py             published attack suite (run: python3 http_attack_harness.py [host] [port] [path])
redteam/                           our own red-team attack scripts (see redteam/NOTES.md)
POSTMORTEM.md                      Exercise 4 write-up
```

`http_attack_harness.py` currently passes clean: no `MUST` failures and no
`SHOULD` gaps. (One `SHOULD` gap did show up during development -- a 5 MB
declared body returned `200` instead of `413` because `MAX_BODY_SIZE` in
`server.py` was set to 10 MiB. Since a `GET` has no legitimate reason to carry
a body anywhere near that large, the limit was tightened to 1 MiB, which
fixed it without touching any real request path.)

## AI assistance

Written with Claude (Anthropic) as a coding assistant: it wrote the initial
implementation of `server.py`/`client.py` from the assignment's spec, which
was then run against hand- and AI-written adversarial inputs, read line by
line, and fixed where its behavior was wrong (see `POSTMORTEM.md` for a
specific example — the bare-LF/CR handling initially degraded to a 15-second
timeout instead of an immediate `400`, which was caught by testing, not by
inspection). All the numbers in this README and the postmortem come from
actually running the server and the attack scripts, not from the assistant's
description of what the code does.

## Partner

Eva Tate and Giselle Wu.
