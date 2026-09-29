# Red-team notes

Four scripts, one per attack family, run against `server.py` on
`localhost:8080`. Each script's own docstring documents what each individual
attack does, why it matters, and what was observed — this file is just the
index plus the one finding worth calling out.

Run them with the server already running:

```
python3 server.py 8080          # in one terminal
python3 redteam/attack_framing.py
python3 redteam/attack_resource_exhaustion.py   # takes ~35s, timing-based
python3 redteam/attack_path_traversal.py
python3 redteam/attack_protocol_edges.py
```

| Script | Covers |
|---|---|
| `attack_framing.py` | conflicting `Content-Length`, `Content-Length` + `Transfer-Encoding`, bare CR/LF, body-longer-than-declared + pipelined request, malformed chunked encoding, whitespace-before-colon header smuggling |
| `attack_resource_exhaustion.py` | Slowloris (trickled headers) with a normal client served concurrently, slow/incomplete body, oversized URI/header/header-count/`Content-Length` |
| `attack_path_traversal.py` | literal `../`, percent-encoded, "double-encoded", null byte, dotfile, own source, bare directory request |
| `attack_protocol_edges.py` | missing/duplicate `Host`, unsupported version, unsupported method carrying a body with a pipelined follow-up |

All four ran clean against the current server: every attack got the
expected status code, the process stayed up throughout, and a normal client
issued mid-attack (in `attack_resource_exhaustion.py`) was served in ~0ms.

## The one finding worth flagging

`attack_framing.py`'s bare-LF/CR case is the interesting one — not because
it currently fails, but because an earlier version of the server failed it
in a subtle way that a canned "send `\n` instead of `\r\n`" test wouldn't
surface on its own. See `POSTMORTEM.md` for the full trace: the short
version is that a parser which only recognizes a well-formed `\r\n\r\n` as
"end of headers" has no way to distinguish a request using illegal line
endings from a request that is simply trickling in slowly — both just look
like "the delimiter hasn't shown up yet." The fix was to scan for a bare CR
or LF explicitly, on every read, and reject immediately rather than waiting
on a delimiter that will never arrive.
