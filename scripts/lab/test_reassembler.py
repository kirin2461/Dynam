#!/usr/bin/env python3
"""Unit tests for dpi-emu.py Reassembler + stream parsers (no NFQUEUE needed).

Run:  python3 scripts/lab/test_reassembler.py
Exit 0 iff every check passes.
"""
import os
import sys

import importlib.util

_dpi_path = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                         "..", "..", "docker", "dpi-emu.py")
_spec = importlib.util.spec_from_file_location("dpi_emu", _dpi_path)
_mod = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(_mod)

Reassembler = _mod.Reassembler
parse_tls_sni = _mod.parse_tls_sni
parse_http_host = _mod.parse_http_host
stream_protocol = _mod.stream_protocol
tls_clienthello_complete = _mod.tls_clienthello_complete
http_headers_complete = _mod.http_headers_complete

PASS = 0
FAIL = 0


def check(name, cond, detail=""):
    global PASS, FAIL
    if cond:
        PASS += 1
        print("  [PASS] %s" % name)
    else:
        FAIL += 1
        print("  [FAIL] %s %s" % (name, detail))


def build_client_hello(sni):
    """Minimal well-formed TLS ClientHello record with a server_name ext."""
    name = sni.encode()
    entry = b"\x00" + len(name).to_bytes(2, "big") + name
    sn_list = len(entry).to_bytes(2, "big") + entry
    ext = b"\x00\x00" + len(sn_list).to_bytes(2, "big") + sn_list
    body = (b"\x03\x03" + b"\x11" * 32 + b"\x00"          # ver, random, sid=""
            + b"\x00\x02\x00\x2f"                         # cipher suites
            + b"\x01\x00"                                 # compression null
            + len(ext).to_bytes(2, "big") + ext)
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def test_in_order():
    r = Reassembler(buffer_limit=16384, ooo_policy="permissive-first")
    r.feed(1000, b"Hello, ")
    r.feed(1007, b"world")
    check("in-order assembly", r.assembled() == b"Hello, world",
          r.assembled())
    check("no anomaly in-order", r.anomaly is None)


def test_overlap_policies():
    # Overlap with DIFFERENT payload bytes at seq 2..3 ("AA" vs "BB").
    r = Reassembler(ooo_policy="strict")
    r.feed(0, b"AAAA")
    r.feed(2, b"BB")
    check("strict: overlap-diff anomaly", r.anomaly is not None, r.anomaly)

    r = Reassembler(ooo_policy="permissive-first")
    r.feed(0, b"AAAA")
    r.feed(2, b"BBCC")
    # overlapped region (seq 2-3) keeps the FIRST segment's bytes ("AA"),
    # the non-overlapping tail of the second segment ("CC") is appended.
    check("permissive-first keeps first bytes", r.assembled() == b"AAAACC",
          r.assembled())

    r = Reassembler(ooo_policy="permissive-last")
    r.feed(0, b"AAAA")
    r.feed(2, b"BBCC")
    check("permissive-last keeps last bytes", r.assembled() == b"AABBCC",
          r.assembled())

    # identical overlap is fine even for strict
    r = Reassembler(ooo_policy="strict")
    r.feed(0, b"AAAA")
    r.feed(2, b"AACC")
    check("strict: identical overlap ok",
          r.anomaly is None and r.assembled() == b"AAAACC",
          (r.anomaly, r.assembled()))


def test_ooo_gap_and_strict_count():
    r = Reassembler(ooo_policy="permissive-first")
    r.feed(0, b"AB")
    r.feed(10, b"KL")
    r.feed(2, b"CDEFGHIJ")
    check("ooo gap filled in order", r.assembled() == b"ABCDEFGHIJKL",
          r.assembled())

    r = Reassembler(ooo_policy="strict", max_ooo=2)
    r.feed(0, b"AB")
    r.feed(10, b"cd")
    r.feed(20, b"ef")
    r.feed(30, b"gh")   # 3rd parked segment > max_ooo=2
    check("strict: >2 ooo segments anomaly",
          r.anomaly is not None and "ooo" in r.anomaly, r.anomaly)


def test_buffer_limit():
    r = Reassembler(buffer_limit=8)
    r.feed(0, b"1234")
    check("limit not reached below cap", not r.limit_reached)
    r.feed(4, b"5678")
    check("limit reached at cap", r.limit_reached)


def test_tls_sni_split():
    ch = build_client_hello("forbidden.example")
    # split INSIDE the SNI string — no single segment carries it whole
    cut = ch.index(b"forbidden") + 4
    r = Reassembler()
    r.feed(0, ch[:cut])
    check("sni not parsed from fragment",
          parse_tls_sni(r.assembled()) is None)
    r.feed(cut, ch[cut:])
    check("sni parsed after reassembly",
          parse_tls_sni(r.assembled()) == "forbidden.example",
          parse_tls_sni(r.assembled()))

    # split across TLS records still parses
    rec1 = ch[:5 + 10]                     # record header + partial hs
    rest = ch[5 + 10:]
    stream = rec1 + b"\x16\x03\x03" + len(rest).to_bytes(2, "big") + rest
    # re-split second record header correctly: rebuild two-record stream
    hs = ch[5:]
    half = len(hs) // 2
    stream = (b"\x16\x03\x01" + half.to_bytes(2, "big") + hs[:half]
              + b"\x16\x03\x03" + (len(hs) - half).to_bytes(2, "big")
              + hs[half:])
    check("sni parsed across 2 TLS records",
          parse_tls_sni(stream) == "forbidden.example", parse_tls_sni(stream))


def test_clienthello_completeness():
    ch = build_client_hello("allowed.example")
    cut = ch.index(b"allowed") + 3
    check("fragment: clienthello incomplete",
          not tls_clienthello_complete(ch[:cut]))
    check("full: clienthello complete", tls_clienthello_complete(ch))
    # ClientHello WITHOUT server_name: complete but no SNI -> DPI must allow
    body = (b"\x03\x03" + b"\x22" * 32 + b"\x00"
            + b"\x00\x02\x00\x2f" + b"\x01\x00"
            + (0).to_bytes(2, "big"))              # zero extensions
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    rec = b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs
    check("no-sni clienthello: complete", tls_clienthello_complete(rec))
    check("no-sni clienthello: sni is None", parse_tls_sni(rec) is None)


def test_http_host():
    r = Reassembler()
    req = b"GET / HTTP/1.1\r\nHost: forbidden.example:8080\r\n\r\n"
    r.feed(0, req[:20])
    check("http: host not parsed from fragment",
          parse_http_host(r.assembled()) is None)
    r.feed(20, req[20:])
    check("http: host parsed (port stripped)",
          parse_http_host(r.assembled()) == "forbidden.example",
          parse_http_host(r.assembled()))
    check("protocol guess http", stream_protocol(r.assembled()) == "http")
    check("protocol guess tls",
          stream_protocol(build_client_hello("x.example")) == "tls")
    check("protocol guess unknown", stream_protocol(b"SSH-2.0-foo") == "unknown")


if __name__ == "__main__":
    test_in_order()
    test_overlap_policies()
    test_ooo_gap_and_strict_count()
    test_buffer_limit()
    test_tls_sni_split()
    test_clienthello_completeness()
    test_http_host()
    print("\nreassembler unit tests: %d passed, %d failed" % (PASS, FAIL))
    sys.exit(1 if FAIL else 0)
