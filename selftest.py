#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-or-later
#
# amule-ec-profiler -- profile aMule's External Connect (EC) protocol.
# Copyright (c) 2026 got3nks
#
# Licensed GPL-2.0-or-later to match aMule, from whose GPL headers the opcode
# and tag tables in ec_codes.py are generated. See LICENSE.
"""Codec and framer tests for the EC profiler. No daemon needed.

    python3 selftest.py

Covers the two things that would silently corrupt every number in a body: the
FSS-UTF codec, and stream reassembly across arbitrary TCP chunk boundaries.
"""

import os
import struct
import sys
import zlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ec_profiler import (  # noqa: E402
    walk_tags,
    EC_FLAG_BASE,
    EC_FLAG_LARGE_TAG_COUNT,
    EC_FLAG_UTF8_NUMBERS,
    EC_FLAG_ZLIB,
    Framer,
    client_ident_from_login,
    fss_decode,
    op_name,
)

FAILED = []


def check(name, ok, detail=""):
    print("  %-52s %s%s" % (name, "ok" if ok else "FAIL", (" -- " + detail) if detail and not ok else ""))
    if not ok:
        FAILED.append(name)


def wctomb(wc):
    """utf8_wctomb from ECSocket.cpp -- the encoder side, for round-tripping."""
    table = [(0x80, 0x00, 0), (0xE0, 0xC0, 6), (0xF0, 0xE0, 12), (0xF8, 0xF0, 18), (0xFC, 0xF8, 24), (0xFE, 0xFC, 30)]
    lmask = [0x7F, 0x7FF, 0xFFFF, 0x1FFFFF, 0x3FFFFFF, 0x7FFFFFFF]
    for i, (_cmask, cval, shift) in enumerate(table):
        if wc <= lmask[i]:
            out = bytearray([cval | (wc >> shift)])
            c = shift
            while c > 0:
                c -= 6
                out.append(0x80 | ((wc >> c) & 0x3F))
            return bytes(out)
    raise ValueError(wc)


FLAGS = EC_FLAG_BASE | EC_FLAG_UTF8_NUMBERS | EC_FLAG_LARGE_TAG_COUNT


def mkpacket(opcode, extra=b"", flags=FLAGS):
    body = wctomb(opcode) + wctomb(0) + extra  # opcode + zero children
    return struct.pack(">II", flags, len(body)) + body


print("FSS-UTF codec")
values = [0, 1, 0x7F, 0x80, 0x7FF, 0x800, 0xFFFF, 0x10000, 0x1FFFFF, 0x200000,
          0x3FFFFFF, 0x4000000, 0x7FFFFFFF, 0x01, 0x02, 0x5F, 1234, 65535, 1000000]
bad = [(v, wctomb(v).hex()) for v in values if fss_decode(wctomb(v), 0) != (v, len(wctomb(v)))]
check("round-trips %d values incl. 5- and 6-byte forms" % len(values), not bad, repr(bad))
check("rejects a truncated sequence", fss_decode(b"\xE0", 0) == (None, 0))
check("rejects a bad continuation byte", fss_decode(b"\xC2\x00", 0) == (None, 0))
check("rejects an over-long encoding", fss_decode(b"\xC0\x80", 0) == (None, 0))
check("empty buffer is not a number", fss_decode(b"", 0) == (None, 0))

print("\nframer reassembly")
stream = mkpacket(0x02) + mkpacket(0x0A, b"\x01" * 40) + mkpacket(0x5F) + mkpacket(0x01)
ref = [(p.opcode, p.wire_len) for p in Framer("t").feed(stream)]
check("parses a 4-packet stream", [op_name(o) for o, _ in ref] ==
      ["EC_OP_AUTH_REQ", "EC_OP_STAT_REQ", "EC_OP_SEARCH_REQUEST_MORE", "EC_OP_NOOP"], repr(ref))

mismatches = []
for cut in range(1, len(stream)):
    f = Framer("t")
    got = [(p.opcode, p.wire_len) for p in f.feed(stream[:cut])]
    got += [(p.opcode, p.wire_len) for p in f.feed(stream[cut:])]
    if got != ref:
        mismatches.append(cut)
check("identical at all %d two-way split points" % (len(stream) - 1), not mismatches, repr(mismatches[:5]))

f = Framer("t")
got = []
for byte in stream:
    got += [(p.opcode, p.wire_len) for p in f.feed(bytes([byte]))]
check("identical fed one byte at a time", got == ref)

f = Framer("t")
check("empty feed yields nothing", f.feed(b"") == [])

print("\nzlib path")
raw = wctomb(0x0A) + wctomb(0)
comp = zlib.compress(raw)
p = Framer("t").feed(struct.pack(">II", EC_FLAG_BASE | EC_FLAG_ZLIB, len(comp)) + comp)[0]
check("inflates and reads the opcode", p.opcode == 0x0A and p.inflated_len == len(raw),
      "opcode=%r logical=%r" % (p.opcode, p.inflated_len))
bogus = b"\x00" * 12
p = Framer("t").feed(struct.pack(">II", EC_FLAG_BASE | EC_FLAG_ZLIB, len(bogus)) + bogus)[0]
check("undecompressable body degrades to unknown", p.opcode is None and p.wire_len == 8 + len(bogus))

print("\ndesync gate")
f = Framer("t")
f.feed(struct.pack(">II", FLAGS, 0x7FFFFFFF))
check("rejects a header past the 256 MB gate", f.desynced and "exceeds" in (f.desync_reason or ""))
f2 = Framer("t")
f2.desynced = True
check("stops parsing once desynced", f2.feed(stream) == [])

print("\nlogin-packet client name")
# EC_OP_AUTH_REQ with one string tag: EC_TAG_CLIENT_NAME = 0x0100 -> "amule-remote"
name = b"amule-remote\x00"
tag = wctomb(0x0100 << 1) + wctomb(6) + wctomb(len(name)) + name
body = wctomb(0x02) + wctomb(1) + tag
check("extracts EC_TAG_CLIENT_NAME", client_ident_from_login(body, FLAGS)[0] == "amule-remote",
      repr(client_ident_from_login(body, FLAGS)))
check("tolerates a truncated login body", client_ident_from_login(body[:6], FLAGS)[0] is None)
check("tolerates a body with no name tag",
      client_ident_from_login(wctomb(0x02) + wctomb(0), FLAGS)[0] is None)

# name + version together, as a real login carries them
tag_v = wctomb(0x0101 << 1) + wctomb(6) + wctomb(len(b"3.1.0\x00")) + b"3.1.0\x00"
body2 = wctomb(0x02) + wctomb(2) + tag + tag_v
check("extracts name and version", client_ident_from_login(body2, FLAGS) == ("amule-remote", "3.1.0"),
      repr(client_ident_from_login(body2, FLAGS)))

print("\nreset behaviour")
from ec_profiler import Stats, Packet  # noqa: E402

st = Stats()
st.client_open(1, "127.0.0.1:5001")          # long-lived, e.g. amulegui
st.client_label(1, "amule-remote", "3.1.0")
st.client_open(2, "127.0.0.1:5002")          # short-lived, e.g. amulecmd
st.client_label(2, "aMulecmd", "GIT")
req = Packet(0x22, 10, 18, 0x02, None, 1.0)
rsp = Packet(0x22, 10, 18, 0x04, None, 1.1)
st.on_packet("c2s", req, 1); st.on_packet("s2c", rsp, 1); st.on_call(req, rsp, 0.1, 1)
st.client_close(2)                            # cid 2 is gone before the reset

check("labels resolve before reset", st._label(1) == "amulegui" and st.clients[1]["calls"] == 1)

st.reset()

check("open connection survives the reset", 1 in st.clients)
check("its identity is intact", st.clients.get(1, {}).get("label") == "amulegui"
      and st.clients.get(1, {}).get("instance") == "amulegui@5001",
      repr(st.clients.get(1)))
check("its counters are zeroed", st.clients.get(1, {}).get("calls") == 0
      and st.clients.get(1, {}).get("c2s_bytes") == 0)
check("closed connection is dropped", 2 not in st.clients)
check("conns_open reflects survivors", st.conns_open == 1 and st.conns_total == 1,
      "open=%r total=%r" % (st.conns_open, st.conns_total))

# the actual symptom: a call after reset must not be attributed to "?"
st.on_call(req, rsp, 0.1, 1)
check("calls after reset keep their caller", st._label(1) == "amulegui"
      and any(k[0] == "amulegui" for k in st.ops), sorted(str(k) for k in st.ops))
check("post-reset call is counted", st.clients[1]["calls"] == 1)

print()
print("per-tag byte accounting")


def mktag(name, dtype, data=b"", children=(), ):
    """Build one tag the way CECTag::WriteTag does.

    The subtle part, and the thing the walker has to mirror: the declared
    length is NOT the wire size. CECTag::GetTagLen sums FIXED-width field
    sizes (2+1+4 per child, plus 2 for a child's own count field) while the
    body FSS-encodes those numbers into fewer bytes. Building the fixture
    with wire sizes instead would let a cursor-measuring walker pass and a
    correct one fail.
    """
    kids = b"".join(c[0] for c in children)
    ideal = sum(c[1] + 7 + (2 if c[2] else 0) for c in children)
    declared = len(data) + ideal
    raw_name = (name << 1) | (1 if children else 0)
    body = (wctomb(len(children)) + kids if children else b"") + data
    wire = wctomb(raw_name) + wctomb(dtype) + wctomb(declared) + body
    return wire, declared, bool(children)


_leafA = mktag(0x0500, 3, b"\x00\x00\x00\x2a")
_s1 = mktag(0x0700, 6, b"abc")
_s2 = mktag(0x0700, 6, b"xyz")
_cont = mktag(0x0600, 6, b"", (_s1, _s2))
_deep = mktag(0x0800, 6, b"", (mktag(0x0900, 6, b"", (_s1, _s2)),))
_body = wctomb(0x21) + wctomb(3) + _leafA[0] + _cont[0] + _deep[0]

_sizes = {}
_end, _ideal = walk_tags(_body, len(wctomb(0x21)), True, False, {}, sizes=_sizes)
check("walks a nested body to the end", _end == len(_body), "%r of %d" % (_end, len(_body)))

# The invariant that makes the numbers trustworthy: every byte of the body
# after the opcode and the root tag count belongs to exactly one tag's self
# total. Containers own their children's count field; children own themselves.
_overhead = len(wctomb(0x21)) + len(wctomb(3))
_self_total = sum(v[1] for v in _sizes.values())
check("sum(self_bytes) reconstructs the body", _self_total == len(_body) - _overhead,
      "self=%d body-overhead=%d" % (_self_total, len(_body) - _overhead))
check("a container's inclusive exceeds its self", _sizes[0x0600][2] > _sizes[0x0600][1],
      repr(_sizes.get(0x0600)))
check("repeated tags accumulate", _sizes[0x0700][0] == 4, repr(_sizes.get(0x0700)))
check("a leaf's self equals its inclusive", _sizes[0x0500][1] == _sizes[0x0500][2],
      repr(_sizes.get(0x0500)))
check("an unparseable body yields no partial tally",
      walk_tags(_body[:len(_body) - 3], len(wctomb(0x21)), True, False, {}, sizes={})[0] is None)
# A declared length shorter than the children already parsed is malformed; the
# reader rejects it rather than wrapping the unsigned subtraction (CECTag guard).
_bad = bytearray(_cont[0]); _bad[2] = 1
check("rejects a declared length below its children",
      walk_tags(wctomb(0x21) + wctomb(1) + bytes(_bad), 1, True, False, {}, sizes={})[0] is None)

print()
if FAILED:
    print("%d FAILED: %s" % (len(FAILED), ", ".join(FAILED)))
    sys.exit(1)
print("all checks passed")
