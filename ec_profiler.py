#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# amule-ec-profiler -- profile aMule's External Connect (EC) protocol.
# Copyright (c) 2026 got3nks
#
# Licensed GPL-2.0-or-later to match aMule, from whose GPL headers the opcode
# and tag tables in ec_codes.py are generated. See LICENSE.
"""
EC protocol profiler -- a pass-through TCP proxy that sits between an EC client
(amulegui / amuleapi / amulecmd / amuleweb) and amuled, and reports what the
link actually costs.

    amulegui  ->  ec_profiler (:4713)  ->  amuled (:4712)

Bytes are forwarded verbatim and never rewritten; the proxy only observes. It
parses enough of each packet to name it (the opcode) and size it, pairs each
client request with the daemon's reply to get a round-trip time, and serves a
live dashboard over HTTP.

Wire format (see src/libs/ec/cpp/ECSocket.cpp):

    bytes 0-3   flags   big-endian uint32
    bytes 4-7   length  big-endian uint32, body bytes that follow
    body[0..]   opcode, then tag count, then tags

The two flags that matter here are mutually exclusive by construction in
CECSocket::WritePacket:

    if (big && zlib_negotiated && !local_bypass) flags |= EC_FLAG_ZLIB;
    else                                         flags |= EC_FLAG_UTF8_NUMBERS;

so "not compressed" implies numbers ARE FSS-UTF encoded -- the opposite of the
naive assumption. On loopback the client sends EC_TAG_PREFER_NO_ZLIB and the
daemon bypasses deflate for everything under 256 MB, so the UTF8 path is what
you will normally see. Both paths are handled regardless of what negotiated.

Usage:
    python3 ec_profiler.py --listen 4713 --target 127.0.0.1:4712
    then point the client at 4713 and open http://127.0.0.1:8899
"""

import argparse
import asyncio
import collections
import json
import os
import signal
import sys
import time
import zlib

try:
    from ec_codes import OPCODES, TAGS  # noqa: F401  (TAGS reserved for tag-level parsing)
except ImportError:  # pragma: no cover - allow running from another cwd
    import sys

    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from ec_codes import OPCODES, TAGS  # noqa: F401

# --- EC constants, mirrored from src/libs/ec/cpp/ECCodes.h -----------------

EC_FLAG_ZLIB = 0x00000001
EC_FLAG_UTF8_NUMBERS = 0x00000002
EC_FLAG_LARGE_TAG_COUNT = 0x00000010
EC_FLAG_BASE = 0x00000020  # always set; unnamed in the enum

EC_HEADER_SIZE = 8

FLAG_NAMES = [
    (EC_FLAG_ZLIB, "ZLIB"),
    (EC_FLAG_UTF8_NUMBERS, "UTF8_NUM"),
    (EC_FLAG_LARGE_TAG_COUNT, "LARGE_TAG_CNT"),
    (EC_FLAG_BASE, "BASE"),
]

# ReadHeader's sanity gate. Anything larger is a desync, not a packet.
EC_MAX_PACKET = 256 * 1024 * 1024

RECENT_LEN = 200  # per-tick tail sent to the dashboard, which accumulates its own log
RTT_SAMPLES = 2000  # per-opcode reservoir for percentiles
THROUGHPUT_SECONDS = 60  # sparkline window


def op_name(code):
    """Human name for an opcode, or a hex placeholder for gaps in the enum."""
    if code is None:
        return "?"
    return OPCODES.get(code, "OP_0x%02X" % code)


def flags_str(flags):
    parts = [name for bit, name in FLAG_NAMES if flags & bit]
    unknown = flags & ~sum(bit for bit, _ in FLAG_NAMES)
    if unknown:
        parts.append("0x%X" % unknown)
    return "|".join(parts) if parts else "0"


# --- FSS-UTF number codec -------------------------------------------------
#
# utf8_mbtowc in ECSocket.cpp is the Unicode-home-page FSS-UTF sample: UTF-8
# shaped, but with 5- and 6-byte forms carrying values up to 0x7FFFFFFF. Python's
# codecs reject those, so decode by hand. Used for every number in the body when
# EC_FLAG_UTF8_NUMBERS is set -- opcode, tag counts, tag lengths.

_FSS_TABLE = [
    # (cmask, cval, shift, lmask, lval)
    (0x80, 0x00, 0 * 6, 0x0000007F, 0x00000000),
    (0xE0, 0xC0, 1 * 6, 0x000007FF, 0x00000080),
    (0xF0, 0xE0, 2 * 6, 0x0000FFFF, 0x00000800),
    (0xF8, 0xF0, 3 * 6, 0x001FFFFF, 0x00010000),
    (0xFC, 0xF8, 4 * 6, 0x03FFFFFF, 0x00200000),
    (0xFE, 0xFC, 5 * 6, 0x7FFFFFFF, 0x04000000),
]


def fss_decode(buf, pos):
    """Decode one FSS-UTF number at buf[pos:].

    Returns (value, next_pos), or (None, pos) if the bytes are truncated or not
    a valid sequence. Mirrors utf8_mbtowc's accept/reject exactly, including its
    over-long rejection (l < lval) and continuation-byte check.
    """
    if pos >= len(buf):
        return None, pos
    c0 = buf[pos]
    value = c0
    n = 0
    for cmask, cval, _shift, lmask, lval in _FSS_TABLE:
        n += 1
        if (c0 & cmask) == cval:
            value &= lmask
            if value < lval:
                return None, pos  # over-long encoding
            return value, pos + n
        if pos + n >= len(buf):
            return None, pos  # truncated
        cont = (buf[pos + n] ^ 0x80) & 0xFF
        if cont & 0xC0:
            return None, pos  # not a continuation byte
        value = (value << 6) | cont
    return None, pos


def read_number(buf, pos, utf8_mode, width):
    """One number off the body: FSS-UTF when negotiated, else big-endian."""
    if utf8_mode:
        return fss_decode(buf, pos)
    if pos + width > len(buf):
        return None, pos
    return int.from_bytes(buf[pos : pos + width], "big"), pos + width


# --- shallow tag walk -----------------------------------------------------
#
# Only used to pull EC_TAG_CLIENT_NAME out of the login packet so a connection
# can label itself ("amulegui" / "amuleapi" / "amulecmd"). Mirrors
# CECTag::ReadFromSocket:
#
#   tagname  uint16   -- low bit is has-children, the name is the value >> 1
#   type     uint8
#   length   uint32   -- INCLUDES the serialized size of any children
#   children (when the has-children bit is set)
#   data     length minus however many bytes the children took
#
# The children-inclusive length is the subtle part; rather than predict it we
# just measure how far the cursor moved.

EC_TAG_CLIENT_NAME = 0x0100
EC_TAG_CLIENT_VERSION = 0x0101
EC_TAGTYPE_STRING = 6  # only type we need to interpret

# How many connections keep per-instance opcode detail. Everything is always
# counted in the per-client-type rollup; this only bounds the finer-grained view
# (and the SSE payload) when a client like amulecmd opens a connection per call.
MAX_LIVE_INSTANCES = 24

# The name each client puts in its login packet, mapped to what people call it.
# amulegui's is the non-obvious one: amule-remote-gui.cpp hardcodes
# "amule-remote". The others come from their ConnectAndRun() call:
#   TextClient.cpp -> "aMulecmd", WebInterface.cpp -> "aMuleweb",
#   webapi/App.cpp -> "amuleapi".
CLIENT_ALIASES = {
    "amule-remote": "amulegui",
    "aMulecmd": "amulecmd",
    "aMuleweb": "amuleweb",
    "amuleapi": "amuleapi",
}


def _read_count(buf, pos, utf8, large):
    n, pos = read_number(buf, pos, utf8, 2)
    if n is None:
        return None, pos
    if large and n == 0xFFFF:
        # Sentinel-extended count. Only legal when LARGE_TAG_COUNT negotiated;
        # otherwise 0xFFFF is a literal count of 65535 and consumes no extra
        # bytes (see CECTag::ReadChildren).
        return read_number(buf, pos, utf8, 4)
    return n, pos


def walk_tags(buf, pos, utf8, large, found, depth=0):
    """Walk one children list, recording {tagname: bytes} for string tags.

    Returns the position after the list, or None if the bytes don't parse.
    Bounded depth: this is a diagnostic aid, not a validating parser.
    """
    if depth > 8:
        return None
    count, pos = _read_count(buf, pos, utf8, large)
    if count is None or count > 1 << 20:
        return None
    for _ in range(count):
        raw_name, pos = read_number(buf, pos, utf8, 2)
        if raw_name is None:
            return None
        has_children = bool(raw_name & 0x01)
        name = raw_name >> 1
        dtype, pos = read_number(buf, pos, utf8, 1)
        if dtype is None:
            return None
        declared, pos = read_number(buf, pos, utf8, 4)
        if declared is None:
            return None
        after_header = pos
        if has_children:
            pos = walk_tags(buf, pos, utf8, large, found, depth + 1)
            if pos is None:
                return None
        data_len = declared - (pos - after_header)
        if data_len < 0 or pos + data_len > len(buf):
            return None
        if name not in found and dtype == EC_TAGTYPE_STRING:
            found[name] = bytes(buf[pos : pos + data_len])
        pos += data_len
    return pos


def client_ident_from_login(body, flags):
    """(name, version) from an EC_OP_AUTH_REQ body; (None, None) if unreadable.

    EC carries no per-instance identifier -- the login is name + version +
    protocol version + a hash of the version string, all identical across two
    copies of the same build. Distinguishing concurrent instances therefore falls
    to the peer's source port; the version is captured because it is the one
    thing that separates an old build from a new one in an A/B run.
    """
    utf8 = bool(flags & EC_FLAG_UTF8_NUMBERS)
    large = bool(flags & EC_FLAG_LARGE_TAG_COUNT)
    opcode, pos = read_number(body, 0, utf8, 1)
    if opcode is None:
        return None, None
    found = {}
    walk_tags(body, pos, utf8, large, found)

    def get(tag):
        raw = found.get(tag)
        if not raw:
            return None
        return raw.rstrip(b"\0").decode("utf-8", "replace") or None

    return get(EC_TAG_CLIENT_NAME), get(EC_TAG_CLIENT_VERSION)


def friendly_client(raw):
    """Display name for a login string, keeping unknown names verbatim."""
    return CLIENT_ALIASES.get(raw, raw)


# --- packet framing -------------------------------------------------------


EC_OP_AUTH_REQ = 0x02

# Bodies are kept only while small, purely so the login packet can be walked for
# the client's name. Anything bigger is measured and dropped.
KEEP_BODY_MAX = 8192


class Packet:
    __slots__ = ("flags", "body_len", "wire_len", "opcode", "inflated_len", "t", "body")

    def __init__(self, flags, body_len, wire_len, opcode, inflated_len, t, body=None):
        self.flags = flags
        self.body_len = body_len
        self.wire_len = wire_len  # header + body, i.e. what crossed the socket
        self.opcode = opcode
        self.inflated_len = inflated_len  # logical size when ZLIB was used
        self.t = t
        self.body = body


class Framer:
    """Reassembles one direction of a connection into packets.

    Fed arbitrary byte chunks; yields whole packets. Sets `desynced` if a header
    fails the sanity gate, after which it stops parsing that direction rather
    than emitting garbage (the bytes still get forwarded -- we only observe).
    """

    def __init__(self, label):
        self.label = label
        self.buf = bytearray()
        self.desynced = False
        self.desync_reason = None

    def feed(self, data):
        if self.desynced:
            return []
        self.buf += data
        out = []
        while True:
            if len(self.buf) < EC_HEADER_SIZE:
                break
            flags = int.from_bytes(self.buf[0:4], "big")
            body_len = int.from_bytes(self.buf[4:8], "big")
            if body_len > EC_MAX_PACKET:
                self.desynced = True
                self.desync_reason = "announced body %d B exceeds the 256 MB gate" % body_len
                break
            total = EC_HEADER_SIZE + body_len
            if len(self.buf) < total:
                break  # wait for the rest
            body = bytes(self.buf[EC_HEADER_SIZE:total])
            del self.buf[:total]
            opcode, inflated_len = self._parse_body(flags, body)
            keep = body if body_len <= KEEP_BODY_MAX else None
            out.append(Packet(flags, body_len, total, opcode, inflated_len, time.monotonic(), keep))
        return out

    @staticmethod
    def _parse_body(flags, body):
        """First number of the body is the opcode. Returns (opcode, inflated_len)."""
        if flags & EC_FLAG_ZLIB:
            # Inflate just enough to read the opcode; the whole body is cheap
            # at these sizes and gives us the logical length for a ratio.
            try:
                plain = zlib.decompress(body)
            except zlib.error:
                return None, None
            opcode, _ = read_number(plain, 0, bool(flags & EC_FLAG_UTF8_NUMBERS), 1)
            return opcode, len(plain)
        opcode, _ = read_number(body, 0, bool(flags & EC_FLAG_UTF8_NUMBERS), 1)
        return opcode, None


# --- statistics -----------------------------------------------------------


class OpStat:
    __slots__ = ("calls", "req_bytes", "resp_bytes", "rtts", "rtt_sum", "rtt_max")

    def __init__(self):
        self.calls = 0
        self.req_bytes = 0
        self.resp_bytes = 0
        self.rtts = collections.deque(maxlen=RTT_SAMPLES)
        self.rtt_sum = 0.0
        self.rtt_max = 0.0

    def add(self, req_bytes, resp_bytes, rtt):
        self.calls += 1
        self.req_bytes += req_bytes
        self.resp_bytes += resp_bytes
        if rtt is not None:
            self.rtts.append(rtt)
            self.rtt_sum += rtt
            self.rtt_max = max(self.rtt_max, rtt)


def pct(sorted_vals, q):
    if not sorted_vals:
        return 0.0
    if len(sorted_vals) == 1:
        return sorted_vals[0]
    idx = min(len(sorted_vals) - 1, int(round(q * (len(sorted_vals) - 1))))
    return sorted_vals[idx]


class Stats:
    def __init__(self):
        self.reset()

    def reset(self):
        # Connections that are still open must survive a reset. Their identity
        # came from a login packet that is long past, so dropping them would
        # attribute every later call to "?" until the client reconnects -- and a
        # long-lived amulegui may not reconnect for hours. Counters are zeroed;
        # identity (label, version, peer, instance) is kept.
        survivors = [c for c in getattr(self, "clients", {}).values() if c["open"]]

        self.start = time.monotonic()
        # Two aggregations, deliberately:
        #   ops      keyed by (client label, opcode) -- every call, forever.
        #            Bounded by the number of distinct client types.
        #   ops_inst keyed by (cid, opcode) -- per-connection detail, pruned to
        #            the most recent MAX_LIVE_INSTANCES connections so a client
        #            that reconnects per call (amulecmd) cannot grow the SSE
        #            payload without bound. Nothing is lost from `ops`.
        self.ops = collections.defaultdict(OpStat)
        self.ops_inst = collections.defaultdict(OpStat)
        self.clients = {}
        self.recent = collections.deque(maxlen=RECENT_LEN)
        self.c2s_bytes = self.s2c_bytes = 0
        self.c2s_pkts = self.s2c_pkts = 0
        self.pushes = 0  # server packets with no request outstanding
        self.desyncs = []
        self.flags_seen = collections.Counter()
        self.zlib_wire = 0
        self.zlib_logical = 0
        self.conns_open = 0
        self.conns_total = 0
        self.pruned_instances = 0
        # per-second throughput buckets, keyed by int(monotonic)
        self.tp = collections.defaultdict(lambda: [0, 0])
        self.seq = 0

        for c in survivors:
            for k in ("c2s_bytes", "s2c_bytes", "c2s_pkts", "s2c_pkts", "calls"):
                c[k] = 0
            self.clients[c["cid"]] = c
        self.conns_open = len(survivors)
        self.conns_total = len(survivors)

    # -- clients
    def client_open(self, cid, peer):
        self.clients[cid] = {
            "cid": cid,
            "label": "?",
            "raw": None,
            "version": None,
            "instance": "?#%d" % cid,
            "peer": peer,
            "port": peer.rsplit(":", 1)[-1] if ":" in peer else "?",
            "c2s_bytes": 0,
            "s2c_bytes": 0,
            "c2s_pkts": 0,
            "s2c_pkts": 0,
            "calls": 0,
            "open": True,
            "opened": time.time(),
            "closed": None,
        }
        self.conns_open += 1
        self.conns_total += 1

    def client_label(self, cid, raw, version):
        c = self.clients.get(cid)
        if not c:
            return
        c["raw"] = raw
        c["version"] = version
        c["label"] = friendly_client(raw)
        # Instance identity: EC has no per-instance id, so this is client type +
        # the peer's source port, which is what actually separates two amulegui
        # on one host. cid keeps it unique if a port is later reused.
        c["instance"] = "%s@%s" % (c["label"], c["port"])

    def client_close(self, cid):
        if cid in self.clients:
            self.clients[cid]["open"] = False
            self.clients[cid]["closed"] = time.time()
        self.conns_open -= 1
        self._prune_instances()

    def _prune_instances(self):
        """Drop per-instance detail for the oldest closed connections.

        Open connections are never pruned. The per-label rollup in `ops` already
        holds every call, so pruning loses granularity, never totals.
        """
        closed = [c for c in self.clients.values() if not c["open"]]
        if len(closed) <= MAX_LIVE_INSTANCES:
            return
        closed.sort(key=lambda c: c["closed"] or 0)
        for c in closed[: len(closed) - MAX_LIVE_INSTANCES]:
            cid = c["cid"]
            for key in [k for k in self.ops_inst if k[0] == cid]:
                del self.ops_inst[key]
            del self.clients[cid]
            self.pruned_instances += 1

    # -- packet accounting
    def on_packet(self, direction, pkt, cid):
        bucket = self.tp[int(pkt.t)]
        self.flags_seen[pkt.flags] += 1
        if pkt.flags & EC_FLAG_ZLIB and pkt.inflated_len:
            self.zlib_wire += pkt.wire_len
            self.zlib_logical += pkt.inflated_len
        c = self.clients.get(cid)
        if direction == "c2s":
            self.c2s_bytes += pkt.wire_len
            self.c2s_pkts += 1
            bucket[0] += pkt.wire_len
            if c:
                c["c2s_bytes"] += pkt.wire_len
                c["c2s_pkts"] += 1
        else:
            self.s2c_bytes += pkt.wire_len
            self.s2c_pkts += 1
            bucket[1] += pkt.wire_len
            if c:
                c["s2c_bytes"] += pkt.wire_len
                c["s2c_pkts"] += 1
        self._trim_tp(int(pkt.t))

    def _trim_tp(self, now_s):
        cutoff = now_s - THROUGHPUT_SECONDS - 2
        for k in [k for k in self.tp if k < cutoff]:
            del self.tp[k]

    # -- call pairing
    def _label(self, cid):
        c = self.clients.get(cid)
        return c["label"] if c else "?"

    def _instance(self, cid):
        c = self.clients.get(cid)
        return c["instance"] if c else "?#%d" % cid

    def on_call(self, req, resp, rtt, cid):
        label = self._label(cid)
        self.ops[(label, req.opcode)].add(req.wire_len, resp.wire_len, rtt)
        self.ops_inst[(cid, req.opcode)].add(req.wire_len, resp.wire_len, rtt)
        c = self.clients.get(cid)
        if c:
            c["calls"] += 1
        self.seq += 1
        self.recent.append(
            {
                "seq": self.seq,
                "ts": time.time(),
                "client": label,
                "instance": self._instance(cid),
                "cid": cid,
                "req": op_name(req.opcode),
                "resp": op_name(resp.opcode),
                "req_bytes": req.wire_len,
                "resp_bytes": resp.wire_len,
                "rtt_ms": None if rtt is None else round(rtt * 1000, 3),
                "flags": flags_str(resp.flags),
                "kind": "call",
            }
        )

    def on_push(self, pkt, cid):
        self.pushes += 1
        self.seq += 1
        self.recent.append(
            {
                "seq": self.seq,
                "ts": time.time(),
                "client": self._label(cid),
                "instance": self._instance(cid),
                "cid": cid,
                "req": "",
                "resp": op_name(pkt.opcode),
                "req_bytes": 0,
                "resp_bytes": pkt.wire_len,
                "rtt_ms": None,
                "flags": flags_str(pkt.flags),
                "kind": "push",
            }
        )

    def on_desync(self, label, reason):
        self.desyncs.append({"where": label, "reason": reason, "ts": time.time()})

    # -- snapshot for the dashboard
    def snapshot(self):
        now = time.monotonic()
        def row(who, code, st):
            q = sorted(st.rtts)
            return {
                    "client": who,
                    "op": op_name(code),
                    "id": "0x%02X" % code if code is not None else "?",
                    "calls": st.calls,
                    "req_bytes": st.req_bytes,
                    "resp_bytes": st.resp_bytes,
                    "total_bytes": st.req_bytes + st.resp_bytes,
                    "avg_resp": round(st.resp_bytes / st.calls) if st.calls else 0,
                    "p50_ms": round(pct(q, 0.50) * 1000, 3),
                    "p99_ms": round(pct(q, 0.99) * 1000, 3),
                    "max_ms": round(st.rtt_max * 1000, 3),
                    "mean_ms": round((st.rtt_sum / len(q)) * 1000, 3) if q else 0,
                    "total_ms": round(st.rtt_sum * 1000, 1),
            }

        rows = [row(label, code, st) for (label, code), st in self.ops.items()]
        inst_rows = [
            row(self.clients[cid]["instance"], code, st)
            for (cid, code), st in self.ops_inst.items()
            if cid in self.clients
        ]
        now_s = int(now)
        series = []
        for sec in range(now_s - THROUGHPUT_SECONDS + 1, now_s + 1):
            b = self.tp.get(sec)
            series.append([b[0], b[1]] if b else [0, 0])
        all_rtts = sorted(r for st in self.ops.values() for r in st.rtts)
        return {
            "uptime": round(now - self.start, 1),
            "totals": {
                "c2s_bytes": self.c2s_bytes,
                "s2c_bytes": self.s2c_bytes,
                "c2s_pkts": self.c2s_pkts,
                "s2c_pkts": self.s2c_pkts,
                "pushes": self.pushes,
                "calls": sum(st.calls for st in self.ops.values()),
                "p50_ms": round(pct(all_rtts, 0.50) * 1000, 3),
                "p99_ms": round(pct(all_rtts, 0.99) * 1000, 3),
                "conns_open": self.conns_open,
                "conns_total": self.conns_total,
                "amplification": (round(self.s2c_bytes / self.c2s_bytes, 1) if self.c2s_bytes else 0),
            },
            "zlib": {
                "packets": sum(n for f, n in self.flags_seen.items() if f & EC_FLAG_ZLIB),
                "wire": self.zlib_wire,
                "logical": self.zlib_logical,
                "ratio": (round(self.zlib_logical / self.zlib_wire, 2) if self.zlib_wire else None),
            },
            "flags_seen": [
                {"flags": "0x%02X" % f, "names": flags_str(f), "packets": n}
                for f, n in sorted(self.flags_seen.items(), key=lambda kv: -kv[1])
            ],
            "ops": rows,
            "ops_inst": inst_rows,
            "clients": sorted(self.clients.values(), key=lambda c: c["cid"]),
            "labels": sorted({c["label"] for c in self.clients.values()}),
            "instances": [c["instance"] for c in sorted(self.clients.values(), key=lambda c: c["cid"])],
            "pruned_instances": self.pruned_instances,
            "recent": list(self.recent)[::-1],
            "throughput": series,
            "desyncs": self.desyncs[-5:],
        }

    # -- end-of-session report
    def report(self):
        """Session summary: counters plus one row per opcode, busiest first."""
        snap = self.snapshot()
        snap.pop("throughput", None)
        snap.pop("recent", None)
        snap["ops"].sort(key=lambda r: (r["client"], -r["total_bytes"]))
        snap["ops_inst"].sort(key=lambda r: (r["client"], -r["total_bytes"]))
        snap["generated"] = time.strftime("%Y-%m-%dT%H:%M:%S%z")
        return snap

    @staticmethod
    def report_text(rep):
        t, z = rep["totals"], rep["zlib"]

        def b(n):
            for unit, div in (("GB", 1 << 30), ("MB", 1 << 20), ("KB", 1 << 10)):
                if n >= div:
                    return "%.1f %s" % (n / div, unit)
            return "%d B" % n

        L = []
        L.append("EC profiler session report   %s" % rep["generated"])
        L.append("=" * 78)
        L.append("duration        %.1f s over %d connection(s)" % (rep["uptime"], t["conns_total"]))
        L.append(
            "client->daemon  %-10s in %d packets" % (b(t["c2s_bytes"]), t["c2s_pkts"])
        )
        L.append(
            "daemon->client  %-10s in %d packets   (%s x amplification)"
            % (b(t["s2c_bytes"]), t["s2c_pkts"], t["amplification"])
        )
        L.append("calls paired    %d   unsolicited pushes %d" % (t["calls"], t["pushes"]))
        L.append("rtt             p50 %.2f ms   p99 %.2f ms" % (t["p50_ms"], t["p99_ms"]))
        if z["packets"]:
            L.append(
                "zlib            %d packet(s), %s wire / %s logical (%sx)"
                % (z["packets"], b(z["wire"]), b(z["logical"]), z["ratio"])
            )
        else:
            L.append("zlib            not used (EC_TAG_PREFER_NO_ZLIB); numbers are FSS-UTF")
        L.append("flags seen      " + ", ".join("%s %s(%d)" % (f["flags"], f["names"], f["packets"]) for f in rep["flags_seen"]))
        for d in rep["desyncs"]:
            L.append("WARNING         parser desync on %s: %s" % (d["where"], d["reason"]))
        L.append("")
        L.append("callers  (instance = client type @ peer source port)")
        L.append(
            "%-20s %-14s %-20s %7s %9s %9s"
            % ("instance", "version", "peer", "calls", "sent", "received")
        )
        L.append("-" * 78)
        for c in rep["clients"]:
            L.append(
                "%-20s %-14s %-20s %7d %9s %9s"
                % (
                    c["instance"][:20],
                    (c["version"] or "-")[:14],
                    c["peer"][:20],
                    c["calls"],
                    b(c["c2s_bytes"]),
                    b(c["s2c_bytes"]),
                )
            )
        if not rep["clients"]:
            L.append("(no connections)")
        if rep.get("pruned_instances"):
            L.append(
                "(+ %d earlier connection(s) pruned from per-instance detail; their calls "
                "remain in the per-type totals below)" % rep["pruned_instances"]
            )

        L.append("")
        L.append("calls by opcode, per caller")
        L.append(
            "%-18s %-6s %-28s %6s %9s %9s %8s %8s"
            % ("client", "id", "request opcode", "calls", "req", "resp", "p50", "p99")
        )
        L.append("-" * 78)
        for r in rep["ops"]:
            L.append(
                "%-18s %-6s %-28s %6d %9s %9s %7.2f %7.2f"
                % (
                    r["client"][:18],
                    r["id"],
                    r["op"],
                    r["calls"],
                    b(r["req_bytes"]),
                    b(r["resp_bytes"]),
                    r["p50_ms"],
                    r["p99_ms"],
                )
            )
        if not rep["ops"]:
            L.append("(no calls observed)")

        if rep.get("ops_inst"):
            L.append("")
            L.append("calls by opcode, per instance")
            L.append(
                "%-20s %-6s %-26s %6s %9s %9s %8s"
                % ("instance", "id", "request opcode", "calls", "req", "resp", "p99")
            )
            L.append("-" * 78)
            for r in sorted(rep["ops_inst"], key=lambda r: (r["client"], -r["total_bytes"])):
                L.append(
                    "%-20s %-6s %-26s %6d %9s %9s %7.2f"
                    % (
                        r["client"][:20],
                        r["id"],
                        r["op"],
                        r["calls"],
                        b(r["req_bytes"]),
                        b(r["resp_bytes"]),
                        r["p99_ms"],
                    )
                )
        return "\n".join(L)


# --- proxy ----------------------------------------------------------------


class Connection:
    """One client <-> daemon session. Owns the pending-request queue.

    Per-connection framers and queue are what let several clients share the
    proxy without corrupting each other's request/response pairing.
    """

    def __init__(self, stats, cid, peer):
        self.stats = stats
        self.cid = cid
        self.labelled = False
        self.pending = collections.deque()
        self.c2s = Framer("client->daemon #%d" % cid)
        self.s2c = Framer("daemon->client #%d" % cid)
        stats.client_open(cid, peer)

    def on_c2s(self, data):
        for pkt in self.c2s.feed(data):
            # The login packet carries EC_TAG_CLIENT_NAME, so a connection can
            # name itself ("amulegui" / "amuleapi" / "amulecmd") instead of
            # showing up as a port number.
            if not self.labelled and pkt.opcode == EC_OP_AUTH_REQ and pkt.body:
                name, version = client_ident_from_login(pkt.body, pkt.flags)
                self.labelled = True
                if name:
                    self.stats.client_label(self.cid, name, version)
            self.stats.on_packet("c2s", pkt, self.cid)
            self.pending.append(pkt)
        self._check_desync(self.c2s)

    def on_s2c(self, data):
        for pkt in self.s2c.feed(data):
            self.stats.on_packet("s2c", pkt, self.cid)
            if self.pending:
                req = self.pending.popleft()
                self.stats.on_call(req, pkt, pkt.t - req.t, self.cid)
            else:
                # amuled only pushes unprompted to clients that advertised
                # EC_TAG_CAN_NOTIFY, and no in-tree client does -- but count it
                # rather than mispair it if one ever shows up.
                self.stats.on_push(pkt, self.cid)
        self._check_desync(self.s2c)

    def _check_desync(self, framer):
        if framer.desynced and framer.desync_reason:
            self.stats.on_desync(framer.label, framer.desync_reason)
            framer.desync_reason = None


async def pump(reader, writer, sink):
    """Forward bytes verbatim, handing a copy to `sink` for observation."""
    try:
        while True:
            data = await reader.read(65536)
            if not data:
                break
            sink(data)
            writer.write(data)
            await writer.drain()
    except (ConnectionResetError, BrokenPipeError, asyncio.IncompleteReadError):
        pass
    finally:
        try:
            writer.close()
        except Exception:
            pass


class Proxy:
    def __init__(self, stats, target_host, target_port):
        self.stats = stats
        self.target_host = target_host
        self.target_port = target_port
        self.next_cid = 0

    async def handle(self, creader, cwriter):
        self.next_cid += 1
        cid = self.next_cid
        sock = cwriter.get_extra_info("peername")
        peer = "%s:%s" % (sock[0], sock[1]) if sock else "?"
        try:
            dreader, dwriter = await asyncio.open_connection(self.target_host, self.target_port)
        except OSError as exc:
            print("[ec-profiler] cannot reach %s:%s (%s)" % (self.target_host, self.target_port, exc))
            cwriter.close()
            return
        conn = Connection(self.stats, cid, peer)
        try:
            await asyncio.gather(
                pump(creader, dwriter, conn.on_c2s),
                pump(dreader, cwriter, conn.on_s2c),
            )
        finally:
            self.stats.client_close(cid)
            for w in (cwriter, dwriter):
                try:
                    w.close()
                except Exception:
                    pass


# --- dashboard HTTP + SSE -------------------------------------------------

HERE = os.path.dirname(os.path.abspath(__file__))


class Dashboard:
    def __init__(self, stats, listen_port, target, shutdown):
        self.stats = stats
        self.listen_port = listen_port
        self.target = target
        # Set when the process is stopping. The SSE loop below is otherwise
        # infinite, and an infinite handler task is exactly what deadlocks
        # asyncio's Server.wait_closed() on Python >= 3.12.
        self.shutdown = shutdown

    async def handle(self, reader, writer):
        try:
            request_line = await asyncio.wait_for(reader.readline(), timeout=10)
            if not request_line:
                return
            parts = request_line.decode("latin-1").split()
            if len(parts) < 2:
                return
            method, path = parts[0], parts[1]
            # drain headers
            while True:
                line = await asyncio.wait_for(reader.readline(), timeout=10)
                if line in (b"\r\n", b"\n", b""):
                    break
            if path.startswith("/events"):
                await self._sse(writer)
            elif path.startswith("/reset"):
                self.stats.reset()
                self._respond(writer, 200, "application/json", b'{"ok":true}')
                await writer.drain()
            elif path in ("/", "/index.html"):
                body = self._page()
                self._respond(writer, 200, "text/html; charset=utf-8", body)
                await writer.drain()
            else:
                self._respond(writer, 404, "text/plain", b"not found")
                await writer.drain()
        except (asyncio.TimeoutError, ConnectionResetError, BrokenPipeError):
            pass
        finally:
            try:
                writer.close()
            except Exception:
                pass

    def _page(self):
        with open(os.path.join(HERE, "dashboard.html"), "rb") as f:
            html = f.read()
        meta = json.dumps({"listen": self.listen_port, "target": self.target}).encode()
        return html.replace(b"/*__META__*/null", meta)

    @staticmethod
    def _respond(writer, code, ctype, body):
        reason = {200: "OK", 404: "Not Found"}.get(code, "OK")
        writer.write(
            ("HTTP/1.1 %d %s\r\n" % (code, reason)).encode()
            + ("Content-Type: %s\r\n" % ctype).encode()
            + ("Content-Length: %d\r\n" % len(body)).encode()
            + b"Cache-Control: no-store\r\nConnection: close\r\n\r\n"
            + body
        )

    async def _sse(self, writer):
        writer.write(
            b"HTTP/1.1 200 OK\r\n"
            b"Content-Type: text/event-stream\r\n"
            b"Cache-Control: no-store\r\n"
            b"Connection: keep-alive\r\n\r\n"
        )
        await writer.drain()
        while not self.shutdown.is_set():
            payload = json.dumps(self.stats.snapshot(), separators=(",", ":"))
            writer.write(b"data: " + payload.encode() + b"\n\n")
            await writer.drain()
            # Sleep a tick, but wake immediately if we are shutting down so the
            # handler returns instead of being cancelled mid-write.
            try:
                await asyncio.wait_for(self.shutdown.wait(), timeout=1.0)
            except asyncio.TimeoutError:
                pass


# --- main -----------------------------------------------------------------


class Startup(Exception):
    """A listener could not be brought up; report it plainly, not as a traceback."""


def write_report(stats, report_dir):
    """Print the session summary and, unless disabled, persist it next to the tool."""
    rep = stats.report()
    text = Stats.report_text(rep)
    print("\n" + text)
    if not report_dir:
        return
    try:
        os.makedirs(report_dir, exist_ok=True)
        stamp = time.strftime("%Y%m%d-%H%M%S")
        base = os.path.join(report_dir, "ec-session-%s" % stamp)
        with open(base + ".json", "w") as f:
            json.dump(rep, f, indent=2)
        with open(base + ".txt", "w") as f:
            f.write(text + "\n")
        print("\n[ec-profiler] report written to %s.{json,txt}" % base)
    except OSError as exc:
        print("[ec-profiler] could not write report: %s" % exc)


def main():
    ap = argparse.ArgumentParser(description="Profile EC traffic between an EC client and amuled.")
    ap.add_argument("--listen", type=int, default=4713, help="port the client connects to (default 4713)")
    ap.add_argument("--target", default="127.0.0.1:4712", help="amuled's real EC endpoint (default 127.0.0.1:4712)")
    ap.add_argument("--web", type=int, default=8899, help="dashboard port (default 8899)")
    ap.add_argument(
        "--bind",
        default="127.0.0.1",
        help="interface for the EC proxy (default 127.0.0.1; use 0.0.0.0 to profile a remote client)",
    )
    ap.add_argument(
        "--web-bind",
        default=None,
        help="interface for the dashboard (default 127.0.0.1 -- deliberately NOT --bind)",
    )
    ap.add_argument(
        "--report-dir",
        default=os.path.join(HERE, "reports"),
        help="where session reports are written (default ./reports)",
    )
    ap.add_argument("--no-report", action="store_true", help="print the summary but do not write files")
    args = ap.parse_args()

    stats_holder = {}
    started = {"ok": False}

    async def runner():
        host, _, port = args.target.rpartition(":")
        target_host, target_port = host or "127.0.0.1", int(port)
        stats = Stats()
        stats_holder["s"] = stats
        loop = asyncio.get_running_loop()
        shutdown = asyncio.Event()
        proxy = Proxy(stats, target_host, target_port)
        dash = Dashboard(stats, args.listen, args.target, shutdown)
        # The dashboard binds loopback unless asked otherwise, even when the EC
        # proxy is on 0.0.0.0: profiling a remote client needs the proxy port
        # reachable, not the stats page.
        web_bind = args.web_bind or "127.0.0.1"

        async def listen(handler, host, port, what):
            try:
                return await asyncio.start_server(handler, host, port)
            except OSError as exc:
                raise Startup(
                    "cannot listen for the %s on %s:%d -- %s.\n"
                    "              Something else already has that port (another ec_profiler?\n"
                    "              check with: lsof -nP -iTCP:%d -sTCP:LISTEN)"
                    % (what, host, port, exc.strerror or exc, port)
                ) from None

        ec_server = await listen(proxy.handle, args.bind, args.listen, "EC proxy")
        web_server = await listen(dash.handle, web_bind, args.web, "dashboard")
        started["ok"] = True

        # Stop on SIGINT *and* SIGTERM: this usually runs in the background, so
        # a plain `kill` is at least as likely as Ctrl-C, and the session report
        # is the whole point of shutting down cleanly.
        stop = loop.create_future()

        def request_stop(signame, sig):
            if not stop.done():
                stop.set_result(signame)
            # Restore the default disposition so a second Ctrl-C always kills
            # the process, however wedged a connection has become.
            try:
                loop.remove_signal_handler(sig)
            except (NotImplementedError, RuntimeError):
                pass

        for signame in ("SIGINT", "SIGTERM"):
            sig = getattr(signal, signame, None)
            if sig is None:
                continue
            try:
                loop.add_signal_handler(sig, request_stop, signame, sig)
            except (NotImplementedError, RuntimeError):  # pragma: no cover - non-POSIX
                pass

        print("[ec-profiler] EC proxy   %s:%d  ->  %s:%d" % (args.bind, args.listen, target_host, target_port))
        print("[ec-profiler] dashboard  http://%s:%d" % (web_bind, args.web))
        if args.bind not in ("127.0.0.1", "::1", "localhost"):
            # The proxy performs no authentication of its own -- it relays to
            # the daemon, which then applies the usual EC password. Still worth
            # saying out loud, and note this also changes what gets measured:
            # a client dialing a non-loopback address may negotiate ZLIB
            # differently than it would against the daemon directly.
            print(
                "[ec-profiler] WARNING: EC proxy is reachable on %s -- anyone who can reach\n"
                "              %s:%d can reach the daemon through it, and a remote client's\n"
                "              ZLIB negotiation will differ from a direct connection."
                % (args.bind, args.bind, args.listen)
            )
        print("[ec-profiler] point the client's EC port at %d, then use it normally" % args.listen)
        print("[ec-profiler] Ctrl-C (or kill) to stop and write the session report")

        try:
            why = await stop
        finally:
            print("\n[ec-profiler] %s received, shutting down" % (stop.done() and stop.result() or "stop"))
            # Deliberately NOT `async with ec_server, web_server:` and no
            # wait_closed(). Since Python 3.12 wait_closed() waits for every
            # active connection handler to return, and both of ours legitimately
            # block indefinitely -- the SSE stream on its tick loop, and pump()
            # on reader.read() for as long as a client stays connected. Awaiting
            # them meant an open dashboard tab hung shutdown forever.
            #
            # So: stop accepting, tell the SSE loops to finish, then return and
            # let asyncio.run() cancel whatever is still parked in a read.
            shutdown.set()
            ec_server.close()
            web_server.close()

    try:
        asyncio.run(runner())
    except KeyboardInterrupt:
        pass
    except Startup as exc:
        print("[ec-profiler] %s" % exc)
        return 2
    finally:
        # Only report on a session that actually ran. Emitting an empty report
        # after a failed bind reads like a crash rather than a startup error.
        if started["ok"] and "s" in stats_holder:
            write_report(stats_holder["s"], None if args.no_report else args.report_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
