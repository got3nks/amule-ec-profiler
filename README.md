# amule-ec-profiler

<img width="1847" height="1289" alt="immagine" src="https://github.com/user-attachments/assets/674f8255-015b-4c33-84af-60c0e752b421" />

A pass-through TCP proxy that sits between an [aMule](https://github.com/amule-org/amule)
External Connect (EC) client and `amuled`, and reports what the link actually
costs — bytes per opcode, calls per caller, round-trip times — with a live
dashboard and a per-session report.

```
amulegui / amuleapi / amulecmd / amuleweb
        │
        ▼  :4743
   ec_profiler.py ────────► dashboard on http://127.0.0.1:8899
        │
        ▼  :4742
     amuled
```

Bytes are forwarded **verbatim and never rewritten** — the proxy only observes.

Python 3.8+, standard library only — no pip install, no build step.

## Running it

```sh
git clone https://github.com/got3nks/amule-ec-profiler
cd amule-ec-profiler

# 1. amuled with EC enabled (AcceptExternalConnections=1, ECPort=4742)
# 2. start the proxy in front of it
python3 ec_profiler.py --listen 4743 --target 127.0.0.1:4742

# 3. point the client at the proxy port instead of the daemon's
amulecmd --host=127.0.0.1 --port=4743 -P <ec-password> -c "statistics"

# 4. open the dashboard
open http://127.0.0.1:8899
```

For **amulegui**, set the host/port in its connection dialog (it has no
`--port` flag — host, port and password come from its config).

Options:

| flag | default | meaning |
|---|---|---|
| `--listen` | `4743` | port the client connects to |
| `--target` | `127.0.0.1:4712` | the daemon's real EC endpoint |
| `--web` | `8899` | dashboard port |
| `--bind` | `127.0.0.1` | interface for the **EC proxy** (`0.0.0.0` to profile a remote client) |
| `--web-bind` | `127.0.0.1` | interface for the **dashboard** — deliberately independent of `--bind` |
| `--report-dir` | `./reports` | where session reports land |
| `--no-report` | off | print the summary but write no files |
| `--tag-detail` | off | account bytes per EC tag inside each response (walks every tag of every packet) |

## What it shows

**Dashboard** — totals and amplification, throughput for the last 60 s
(hover for a crosshair readout), a callers table, a sortable per-opcode table
(calls / request bytes / response bytes / p50 / p99 / max / cumulative time),
observed packet flags, and a live call log that accumulates in the browser with
**pause** and **clear**. Every panel except the throughput chart can be filtered
to one caller.

**Reset stats** zeroes the counters but keeps the identity of connections that
are still open — their login packet is long past, so dropping them would
attribute every later call to `?` until the client happened to reconnect.
Connections that had already closed are discarded.

**Session report** — on `Ctrl-C` *or* `SIGTERM`, the counters plus a per-caller
and per-opcode breakdown are printed and written to
`reports/ec-session-<stamp>.{json,txt}`. The JSON is the same structure the
dashboard consumes, so sessions can be diffed.

Multiple clients can use the proxy at once. Each connection gets its own framer
pair and its own pending-request queue, so concurrent sessions cannot corrupt
each other's request/response pairing; stats are attributed per caller.

## Where the bytes go, per tag

`--tag-detail` breaks each response down by EC tag. Click an opcode row for the
totals across every call, or a row in the live log for that one call.

Each tag gets two numbers, and the difference matters:

- **self** — the tag's own header, the child-count field it owns, and its own
  data, *excluding* children.
- **inclusive** — its whole wire span, children included.

The on-wire length field includes children, so summing inclusive double-counts
every container. Sorting by self tells you where the bytes actually are;
inclusive tells you what they hang under. Summing self across every tag
reconstructs the body exactly (minus the opcode and the root tag count) — the
selftest asserts this, because it is the property that makes the numbers
trustworthy.

One subtlety the walker has to honour: `CECTag::GetTagLen` computes the declared
length from *fixed-width* field sizes, while the body FSS-encodes those same
numbers into fewer bytes. A tag's own data length is therefore
`declared - GetTagLen(children)`, not `declared - (bytes the cursor moved)`.
The two only agree for a flat tag list.

## Callers name themselves

The EC login packet carries `EC_TAG_CLIENT_NAME`, so connections label
themselves rather than showing up as port numbers. The raw login string is kept
visible next to the friendly name:

| binary | login string | shown as |
|---|---|---|
| amulegui | `amule-remote` | amulegui |
| amulecmd | `aMulecmd` | amulecmd |
| amuleweb | `aMuleweb` | amuleweb |
| amuleapi | `amuleapi` | amuleapi |

Anything else is shown verbatim. `amule-remote` is hardcoded in
`amule-remote-gui.cpp`; the rest come from each binary's `ConnectAndRun()` call.

### Telling apart several copies of the same client

EC carries **no per-instance identifier**. The login is name + version +
protocol version + a hash of the version string — two copies of the same build
are byte-identical on the wire. The only thing that separates concurrent
instances is the peer's **source port**, so that is the instance identity:

```
amulegui@60402    amulegui@60418    amulegui@60433
```

The **group by** selector switches every panel between *client type* (all
amulegui summed — good for amulegui-vs-amuleapi) and *instance* (each connection
separately — good for "which of my three guis is chatty"). The client version is
captured too, which separates an old build from a new one in an A/B run, though
it does not help when the instances are the same build.

Because ports are opaque, **click an instance name in the Callers table to
nickname it**. Nicknames are stored in `localStorage`, keyed by instance, and
apply across the tables and the log.

Per-instance detail is kept for the most recent `MAX_LIVE_INSTANCES` (24)
connections; older *closed* ones are pruned so a client that reconnects per call
(amulecmd does) cannot grow memory or the SSE payload without bound. Pruning
only ever loses granularity — every call stays counted in the per-type view, and
both the dashboard and the session report say when it has happened.

## How the wire format is read

From `src/libs/ec/cpp/ECSocket.cpp` and `ECTag.cpp`:

```
bytes 0-3   flags   big-endian uint32
bytes 4-7   length  big-endian uint32, body bytes to follow
body[0..]   opcode, then tag count, then tags
```

Two things are easy to get wrong:

**`EC_FLAG_ZLIB` and `EC_FLAG_UTF8_NUMBERS` are mutually exclusive.**
`CECSocket::WritePacket` does:

```cpp
if (big && zlib_negotiated && !local_bypass) flags |= EC_FLAG_ZLIB;
else                                         flags |= EC_FLAG_UTF8_NUMBERS;
```

So *not compressed* means numbers **are** FSS-UTF encoded — the opposite of the
naive assumption. On loopback the client sends `EC_TAG_PREFER_NO_ZLIB` and the
daemon bypasses deflate for everything under 256 MB, so the FSS-UTF path is what
you normally see. Both are handled.

**The encoding is FSS-UTF, not UTF-8.** `utf8_mbtowc` is the Unicode-home-page
sample, which admits 5- and 6-byte forms up to `0x7FFFFFFF`. Python's codecs
reject those, so the decoder here is hand-rolled and mirrors the accept/reject
rules exactly (including over-long rejection).

**Tag lengths include their children.** `CECTag::ReadFromSocket` computes
`data_len = declared_len - children_serialized_len`, so the walker measures how
far the cursor moved rather than predicting it.

Opcode and tag name tables are generated from aMule's `ECCodes.h`. The checked-in
`ec_codes.py` covers 87 opcodes and 391 tags; regenerate it against a newer aMule
if the protocol gains codes:

```sh
./regen_codes.sh /path/to/amule        # checkout root, not src/
```

`ECCodes.h` is the hand-maintained master (`ECCodes.java` in the aMule tree is
stale and should be ignored). An unrecognised opcode is shown as `OP_0x??`
rather than breaking anything, so regenerating is optional.

## Caveats worth knowing

**An encrypted EC session is opaque to the profiler — turn encryption off, or
you are measuring ciphertext.** Since AEAD landed, clients negotiate an
encrypted session by default whenever the daemon supports it, and everything
after the login handshake becomes unreadable. Nothing crashes and no warning is
printed: opcodes simply decode as `?` or nonsense like `OP_0x635`, packets are
still sized correctly, and the per-tag breakdown comes back empty. It reads like
a parser bug, and it is not.

To profile a real session, disable encryption on the client:

- **amuleGUI** — untick *Encryption* in the connection dialog, or set
  `Encryption=0` under `[EC]` in its `remote.conf`.
- **amuleapi / amulecmd** — pass `--disable-ec-encryption`.

The login packets stay readable either way, which is why the client still names
itself correctly while everything after it is noise. If most opcodes show as `?`
and the tag columns are empty, check this first.

**The proxy can change what it measures, on non-loopback setups.** The no-zlib
decision is made by the *client*, from the address it dialed
(`m_preferNoZlib = IsLoopbackIP(resolved_ip) || IsLanIP(...)`). A **remote**
amulegui pointed at a proxy running on the daemon host will start sending
`EC_TAG_PREFER_NO_ZLIB` where it previously would not, changing compression
behaviour. For remote-vs-local comparisons, run the proxy on the *client* side.
Both on loopback, nothing changes.

**Round-trip times are FIFO-paired.** `amuled` can push unsolicited packets, but
only to clients that advertise `EC_TAG_CAN_NOTIFY`, and every in-tree client
passes `canNotify = false`. A server packet arriving with no request outstanding
is counted as a push and excluded from RTT rather than mispaired; the dashboard
says so if it ever happens.

**RTT is measured at the proxy**, from the last byte of the request leaving to
the last byte of the response arriving — so it includes daemon processing plus
one loopback hop each way, and is a slight overestimate of what the client sees
directly. On loopback the proxy's own overhead is microseconds.

**Sizes are wire bytes** (header + body). When a packet *is* deflated, the
dashboard also reports the logical size and the ratio.

**Parser desync is contained.** If a header fails the 256 MB sanity gate, that
direction stops being parsed and the dashboard says so — byte forwarding is
unaffected, so the client keeps working.

**Bodies are buffered only up to 8 KB**, purely so the login packet can be
walked for the client name. Larger packets are measured and dropped.

**`--bind 0.0.0.0` exposes the daemon, not just the proxy.** The proxy performs
no authentication of its own — it relays, and the daemon then applies the usual
EC password — so anyone who can reach the proxy port can reach the daemon
through it. The dashboard has its own `--web-bind` (loopback by default) so
profiling a remote client does not also publish the stats page. A warning is
printed whenever the proxy binds a non-loopback address.

## Files

| file | what it is |
|---|---|
| `ec_profiler.py` | the proxy, parser, stats and dashboard server |
| `dashboard.html` | the dashboard; edited live, re-read on each request |
| `ec_codes.py` | generated opcode/tag tables — do not hand-edit |
| `regen_codes.sh` | regenerates `ec_codes.py` from `ECCodes.h` |
| `selftest.py` | codec and framer tests, no daemon needed |
| `LICENSE` | GPL-2.0 |
| `reports/` | session reports — gitignored, they contain real peer addresses |

## Tests

```sh
python3 selftest.py
```

25 checks over the FSS-UTF codec, stream reassembly at every byte boundary, the
zlib path, the desync gate, login parsing and reset semantics. No daemon needed.

## Licence and attribution

GPL-2.0-or-later, matching [aMule](https://github.com/amule-org/amule).

`ec_codes.py` is generated from aMule's `src/libs/ec/cpp/ECCodes.h`, and the wire
format documented above was derived by reading `ECSocket.cpp` and `ECTag.cpp`.
aMule is Copyright (c) the aMule Team. This tool is not affiliated with or
endorsed by the aMule project.
