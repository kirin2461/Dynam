#!/usr/bin/env python3
"""
pcap_assert.py — assertion toolkit for Dynam DPI-lab packet captures.

Runs a set of named checks against a pcap file using tshark (subprocess only,
no external python dependencies) and prints a JSON report.

Usage:
    pcap_assert.py <file.pcap> --check <name> [--check <name> ...] [options]

Checks (with their assert options):
    split-positions  Reconstruct C->S segments of the first TLS ClientHello:
                     segment boundaries, SNI offset in the reassembled stream,
                     sni_split flag, "SNI visible in a single frame" flag.
                     Asserts: --expect-sni-split / --expect-no-sni-split,
                              --expect-sni-single-frame / --expect-no-sni-single-frame
    seq-ack          Sequence-space continuity C->S plus counters of
                     retransmissions / dup-acks / fast retransmissions.
                     Assert: --expect-max-retrans N (default: no bound)
    tls-version      Negotiated TLS version from the first ServerHello
                     (supported_versions extension wins over legacy_version).
                     Assert: --expect-tls-version 1.2|1.3
    alpn             ALPN protocol from the first ServerHello.
                     Assert: --expect-alpn h2|http/1.1|none
    http2            Presence of HTTP/2 frames.
                     Assert: --expect-http2 present|absent
    quic             Presence of QUIC frames.
                     Assert: --expect-quic present|absent
    rst-injection    First RST from the server/DPI side arrives after a
                     ClientHello and before any server application data
                     (proof of an injected RST, not a normal teardown).
                     Assert: --expect-rst-injection injected|none

The generic --expect VALUE is a shortcut: it is applied to every requested
check whose value domain contains VALUE (e.g. "--expect 1.3" only affects
tls-version, "--expect injected" only rst-injection). Per-check options take
precedence over --expect.

Exit codes: 0 = all checks pass, 1 = at least one check failed,
            2 = usage / tooling error.

NOTE: TCP checksum validation is intentionally NOT used anywhere — captures
taken on veth/bridge interfaces show "bad" checksums due to TX offloading.
"""

import argparse
import ipaddress
import json
import subprocess
import sys

TLS_VERSION_NAMES = {
    0x0301: "1.0",
    0x0302: "1.1",
    0x0303: "1.2",
    0x0304: "1.3",
}

TCP_FLAG_RST = 0x04


class CheckError(Exception):
    """Fatal check error (missing data, tshark failure, ...)."""


# --------------------------------------------------------------------------
# tshark helpers
# --------------------------------------------------------------------------

def tshark_fields(pcap, fields, display_filter=None):
    """Run tshark and return a list of rows (each row = list of field strings).

    A field that tshark repeats within one frame (e.g. tcp.segment) is
    returned comma-joined by tshark itself; callers split when needed.
    """
    cmd = ["tshark", "-r", pcap, "-n", "-l"]
    if display_filter:
        cmd += ["-Y", display_filter]
    cmd += ["-T", "fields", "-E", "separator=\t", "-E", "occurrence=a"]
    for f in fields:
        cmd += ["-e", f]
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    if proc.returncode != 0:
        err = proc.stderr.decode(errors="replace").strip()
        # Strip the harmless "Running as user root" warning if it is all we got.
        lines = [l for l in err.splitlines()
                 if "Running as user" not in l and "could be dangerous" not in l]
        if lines:
            raise CheckError("tshark failed: %s" % "; ".join(lines))
    rows = []
    for line in proc.stdout.decode(errors="replace").splitlines():
        if line.strip():
            rows.append(line.split("\t"))
    return rows


def tshark_count(pcap, display_filter):
    """Count frames matching a display filter."""
    rows = tshark_fields(pcap, ["frame.number"], display_filter)
    return len(rows)


def _to_int(s, base=10, default=None):
    try:
        return int(s, base)
    except (TypeError, ValueError):
        return default


# --------------------------------------------------------------------------
# Flow discovery
# --------------------------------------------------------------------------

def find_first_clienthello(pcap, client=None, server=None, stream=None):
    """Locate the first TLS ClientHello frame and its flow.

    Returns dict with: frame, stream, client, server, sni, seq, len,
    segment_frames (list of frame numbers that carried the CH, in wire order).
    """
    filt = "tls.handshake.type==1"
    if stream is not None:
        filt += " && tcp.stream==%d" % stream
    if client:
        filt += " && ip.src==%s" % client
    rows = tshark_fields(
        pcap,
        ["frame.number", "tcp.stream", "ip.src", "ip.dst", "tcp.seq",
         "tcp.len", "tls.handshake.extensions_server_name", "tcp.segment"],
        filt)
    if not rows:
        raise CheckError("no TLS ClientHello found in capture")
    r = rows[0]
    ch = {
        "frame": _to_int(r[0]),
        "stream": _to_int(r[1]),
        "client": r[2],
        "server": r[3],
        "seq": _to_int(r[4]),
        "len": _to_int(r[5], default=0),
        "sni": r[6] or None,
        # tcp.segment lists frame numbers of the reassembled segments.
        "segment_frames": [int(x) for x in r[7].split(",") if x.strip()]
                          if len(r) > 7 and r[7] else [],
    }
    if not ch["segment_frames"]:
        ch["segment_frames"] = [ch["frame"]]
    if client and ch["client"] != client:
        raise CheckError("first ClientHello is not from %s" % client)
    if server and ch["server"] != server:
        raise CheckError("first ClientHello is not to %s" % server)
    return ch


def stream_frames(pcap, stream):
    """All frames of a TCP stream with the fields needed for reconstruction.

    Payload comes from tcp.payload (always populated); tcp.segment_data is
    only a fallback — it is populated solely for frames that took part in a
    desegmentation, which single-frame ClientHellos never do.
    """
    rows = tshark_fields(
        pcap,
        ["frame.number", "ip.src", "tcp.seq", "tcp.len", "tcp.flags",
         "tcp.payload", "tcp.segment_data"],
        "tcp.stream==%d" % stream)
    frames = []
    for r in rows:
        payload = r[5] if len(r) > 5 else ""
        seg_data = r[6] if len(r) > 6 else ""
        raw = payload or seg_data
        frames.append({
            "frame": _to_int(r[0]),
            "src": r[1],
            "seq": _to_int(r[2], default=0),
            "len": _to_int(r[3], default=0),
            "flags": _to_int(r[4], base=16, default=0),
            # tcp.payload/segment_data may repeat per frame -> comma-joined.
            "data": bytes.fromhex(raw.replace(",", "")) if raw else b"",
        })
    return frames


def reconstruct_segments(frames, client, segment_frames=None):
    """Return ordered list of {frame, seq, len, data} for C->S data frames.

    If segment_frames is given, restrict to those frame numbers (the frames
    tshark identified as the ClientHello reassembly members).
    """
    segs = []
    for f in frames:
        if f["src"] != client or f["len"] <= 0:
            continue
        if segment_frames is not None and f["frame"] not in segment_frames:
            continue
        segs.append({"frame": f["frame"], "seq": f["seq"], "len": f["len"],
                     "data": f["data"]})
    segs.sort(key=lambda s: (s["seq"], s["frame"]))
    return segs


def assemble_stream(segments):
    """Assemble a byte stream from segments (first-wins on overlaps).

    Returns (bytes, base_seq). Overlapping/retransmitted bytes that arrive
    later are ignored — matching a 'trust the first segment' model, which is
    what matters for locating the SNI the DPI would have seen.
    """
    if not segments:
        return b"", 0
    base = min(s["seq"] for s in segments)
    buf = {}
    for s in segments:
        for i, b in enumerate(s["data"]):
            buf.setdefault(s["seq"] - base + i, b)
    if not buf:
        return b"", base
    top = max(buf) + 1
    out = bytearray(top)
    for off, b in buf.items():
        out[off] = b
    return bytes(out), base


# --------------------------------------------------------------------------
# Checks
# --------------------------------------------------------------------------

# Valid values of the generic --expect option per check.
EXPECT_DOMAINS = {
    "tls-version": {"1.0", "1.1", "1.2", "1.3"},
    "alpn": {"h2", "http/1.1", "none"},
    "http2": {"present", "absent"},
    "quic": {"present", "absent"},
    "rst-injection": {"injected", "none"},
}


def _expect(args, check_name):
    """Resolve the expected value for a check: per-check option wins, then
    the generic --expect if its value belongs to the check's domain."""
    specific = getattr(args, "expect_" + check_name.replace("-", "_"), None)
    if specific:
        return specific
    domain = EXPECT_DOMAINS.get(check_name, ())
    for val in args.expect or []:
        if val in domain:
            return val
    return None

def check_split_positions(pcap, args):
    """Reconstruct C->S segmentation of the first ClientHello."""
    ch = find_first_clienthello(pcap, client=args.client or None,
                                server=args.server or None,
                                stream=args.stream)
    client = args.client or ch["client"]
    frames = stream_frames(pcap, ch["stream"])
    segs = reconstruct_segments(frames, client, set(ch["segment_frames"]))
    if not segs:
        raise CheckError("no client data segments found for stream %d"
                         % ch["stream"])

    stream_bytes, base = assemble_stream(segs)
    sni = args.sni or ch["sni"]
    details = {
        "stream": ch["stream"],
        "client": client,
        "server": ch["server"],
        "clienthello_frame": ch["frame"],
        "segments": [{"frame": s["frame"], "seq": s["seq"], "len": s["len"]}
                     for s in segs],
        "segment_sizes": [s["len"] for s in segs],
        "reassembled_len": len(stream_bytes),
        "sni": sni,
        "sni_offset": None,
        "sni_split": None,
        "sni_visible_in_single_frame": None,
    }
    assertions = []

    if sni:
        sni_bytes = sni.encode()
        off = stream_bytes.find(sni_bytes)
        details["sni_offset"] = off if off >= 0 else None
        if off < 0:
            assertions.append(("sni_found_in_reassembly", False,
                               "SNI %r not found in reassembled C->S stream"
                               % sni))
        else:
            sni_start = base + off
            sni_end = sni_start + len(sni_bytes)  # exclusive
            # Does any single CH segment hold the whole SNI?
            holder = [s for s in segs
                      if s["seq"] <= sni_start
                      and s["seq"] + s["len"] >= sni_end]
            details["sni_split"] = not holder
            details["sni_visible_in_single_frame"] = bool(holder)
            details["sni_segment_span"] = {
                "start_seq": sni_start, "end_seq": sni_end,
            }
    else:
        assertions.append(("sni_present", False,
                           "no SNI dissected and no --sni given"))

    # Assert expectations.
    if args.expect_sni_split:
        assertions.append(("sni_split", details["sni_split"] is True,
                           "expected SNI to be split across segments"))
    if args.expect_no_sni_split:
        assertions.append(("sni_split", details["sni_split"] is False,
                           "expected SNI NOT to be split"))
    if args.expect_sni_single_frame:
        assertions.append(("sni_visible_in_single_frame",
                           details["sni_visible_in_single_frame"] is True,
                           "expected SNI fully visible in a single frame"))
    if args.expect_no_sni_single_frame:
        assertions.append(("sni_visible_in_single_frame",
                           details["sni_visible_in_single_frame"] is False,
                           "expected SNI NOT fully visible in a single frame"))
    return details, assertions


def check_seq_ack(pcap, args):
    """C->S sequence-space continuity + retransmission counters."""
    ch = find_first_clienthello(pcap, client=args.client or None,
                                server=args.server or None,
                                stream=args.stream)
    client = args.client or ch["client"]
    frames = stream_frames(pcap, ch["stream"])
    segs = reconstruct_segments(frames, client)

    gaps = []
    overlaps = []
    prev_end = None
    for s in segs:
        if prev_end is not None:
            if s["seq"] > prev_end:
                gaps.append({"after_frame": s["frame"],
                             "missing_bytes": s["seq"] - prev_end})
            elif s["seq"] < prev_end:
                overlaps.append({"frame": s["frame"],
                                 "overlap_bytes": prev_end - s["seq"]})
        prev_end = max(prev_end or 0, s["seq"] + s["len"])

    retrans = tshark_count(pcap, "tcp.analysis.retransmission")
    fast_retrans = tshark_count(pcap, "tcp.analysis.fast_retransmission")
    dup_acks = tshark_count(pcap, "tcp.analysis.duplicate_ack")

    details = {
        "stream": ch["stream"],
        "client": client,
        "segments": len(segs),
        "seq_space_end": prev_end,
        "gaps": gaps,
        "overlaps": overlaps,
        "continuous": not gaps,
        "retransmissions": retrans,
        "fast_retransmissions": fast_retrans,
        "duplicate_acks": dup_acks,
    }
    assertions = [("seq_space_continuous", not gaps,
                   "gaps in C->S sequence space: %s" % gaps)]
    if args.expect_max_retrans is not None:
        assertions.append(("retransmissions_within_bound",
                           retrans <= args.expect_max_retrans,
                           "retransmissions %d > allowed %d"
                           % (retrans, args.expect_max_retrans)))
    return details, assertions


def _first_serverhello(pcap, stream=None):
    filt = "tls.handshake.type==2"
    if stream is not None:
        filt += " && tcp.stream==%d" % stream
    rows = tshark_fields(
        pcap,
        ["frame.number", "tcp.stream", "tls.handshake.version",
         # Note: tshark 3.2 spells it with a dot; newer accepts both.
         "tls.handshake.extensions.supported_version",
         "tls.handshake.extensions_alpn_str"],
        filt)
    if not rows:
        return None
    r = rows[0]
    legacy = _to_int(r[2], base=16)
    supported = _to_int(r[3], base=16)
    negotiated = supported if supported else legacy
    return {
        "frame": _to_int(r[0]),
        "stream": _to_int(r[1]),
        "legacy_version": TLS_VERSION_NAMES.get(legacy, hex(legacy or 0)),
        "supported_version": TLS_VERSION_NAMES.get(supported)
                             if supported else None,
        "negotiated": TLS_VERSION_NAMES.get(negotiated, hex(negotiated or 0)),
        "alpn": (r[4] or "none") if len(r) > 4 else "none",
    }


def check_tls_version(pcap, args):
    sh = _first_serverhello(pcap, stream=args.stream)
    if sh is None:
        raise CheckError("no ServerHello found in capture")
    details = dict(sh)
    assertions = []
    expect = _expect(args, "tls-version")
    if expect:
        assertions.append(("tls_version", sh["negotiated"] == expect,
                           "expected TLS %s, got %s"
                           % (expect, sh["negotiated"])))
    return details, assertions


def check_alpn(pcap, args):
    sh = _first_serverhello(pcap, stream=args.stream)
    if sh is None:
        raise CheckError("no ServerHello found in capture")
    details = {"alpn": sh["alpn"], "serverhello_frame": sh["frame"]}
    assertions = []
    expect = _expect(args, "alpn")
    if expect:
        assertions.append(("alpn", sh["alpn"] == expect,
                           "expected ALPN %s, got %s" % (expect, sh["alpn"])))
    return details, assertions


def check_http2(pcap, args):
    n = tshark_count(pcap, "http2")
    details = {"http2_frames": n, "present": n > 0}
    assertions = []
    expect = _expect(args, "http2")
    if expect:
        want = expect == "present"
        assertions.append(("http2", (n > 0) == want,
                           "expected http2 %s, frames=%d" % (expect, n)))
    return details, assertions


def check_quic(pcap, args):
    n = tshark_count(pcap, "quic")
    udp443 = tshark_count(pcap, "udp.port==443 && udp.length>8")
    details = {"quic_frames": n, "present": n > 0,
               "udp443_datagrams": udp443}
    assertions = []
    expect = _expect(args, "quic")
    if expect:
        want = expect == "present"
        assertions.append(("quic", (n > 0) == want,
                           "expected quic %s, frames=%d" % (expect, n)))
    return details, assertions


def check_rst_injection(pcap, args):
    """RST from the server/DPI side after ClientHello but before server data."""
    ch = find_first_clienthello(pcap, client=args.client or None,
                                server=args.server or None,
                                stream=args.stream)
    client = args.client or ch["client"]
    server = args.server or ch["server"]
    frames = stream_frames(pcap, ch["stream"])

    server_frames = [f for f in frames if f["src"] == server]
    first_server_data = next((f for f in server_frames if f["len"] > 0), None)
    first_rst = next((f for f in server_frames
                      if f["flags"] & TCP_FLAG_RST), None)

    injected = (first_rst is not None
                and first_rst["frame"] > ch["frame"]
                and (first_server_data is None
                     or first_rst["frame"] < first_server_data["frame"]))
    details = {
        "stream": ch["stream"],
        "clienthello_frame": ch["frame"],
        "first_server_rst_frame": first_rst["frame"] if first_rst else None,
        "first_server_rst_seq": first_rst["seq"] if first_rst else None,
        "first_server_data_frame": (first_server_data["frame"]
                                    if first_server_data else None),
        "after_clienthello": bool(first_rst
                                  and first_rst["frame"] > ch["frame"]),
        "before_server_data": bool(first_rst and (
            first_server_data is None
            or first_rst["frame"] < first_server_data["frame"])),
        "injected": injected,
    }
    assertions = []
    expect = _expect(args, "rst-injection")
    if expect:
        want = expect == "injected"
        assertions.append(("rst_injection", injected == want,
                           "expected rst-injection=%s, got injected=%s"
                           % (expect, injected)))
    return details, assertions


CHECKS = {
    "split-positions": check_split_positions,
    "seq-ack": check_seq_ack,
    "tls-version": check_tls_version,
    "alpn": check_alpn,
    "http2": check_http2,
    "quic": check_quic,
    "rst-injection": check_rst_injection,
}


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def main(argv=None):
    ap = argparse.ArgumentParser(
        description="Assertion toolkit for Dynam DPI-lab pcap captures.")
    ap.add_argument("pcap", help="pcap file to inspect")
    ap.add_argument("--check", action="append", required=True,
                    choices=sorted(CHECKS),
                    help="check to run (repeatable)")
    ap.add_argument("--client", help="client IPv4/IPv6 address "
                                     "(default: source of first ClientHello)")
    ap.add_argument("--server", help="server IPv4/IPv6 address")
    ap.add_argument("--stream", type=int,
                    help="restrict analysis to this tcp.stream")
    ap.add_argument("--sni", help="expected SNI hostname "
                                  "(default: dissected value)")
    ap.add_argument("--expect", action="append",
                    help="generic expected value (repeatable); applied to "
                         "every requested check whose value domain "
                         "contains it")
    ap.add_argument("--expect-tls-version", choices=["1.0", "1.1", "1.2", "1.3"],
                    help="assert negotiated TLS version")
    ap.add_argument("--expect-alpn",
                    help="assert negotiated ALPN (h2|http/1.1|none)")
    ap.add_argument("--expect-http2", choices=["present", "absent"],
                    help="assert HTTP/2 presence")
    ap.add_argument("--expect-quic", choices=["present", "absent"],
                    help="assert QUIC presence")
    ap.add_argument("--expect-rst-injection", choices=["injected", "none"],
                    help="assert RST injection verdict")
    ap.add_argument("--expect-sni-split", action="store_true",
                    help="assert SNI is split across TCP segments")
    ap.add_argument("--expect-no-sni-split", action="store_true",
                    help="assert SNI is NOT split")
    ap.add_argument("--expect-sni-single-frame", action="store_true",
                    help="assert SNI fully visible in a single frame")
    ap.add_argument("--expect-no-sni-single-frame", action="store_true",
                    help="assert SNI NOT fully visible in a single frame")
    ap.add_argument("--expect-max-retrans", type=int,
                    help="assert retransmission count <= N")
    ap.add_argument("--pretty", action="store_true",
                    help="pretty-print the JSON report")
    args = ap.parse_args(argv)

    # Validate client/server early for a clearer error message.
    for name in ("client", "server"):
        val = getattr(args, name)
        if val:
            try:
                ipaddress.ip_address(val)
            except ValueError:
                print(json.dumps({"error": "invalid --%s %r" % (name, val)}))
                return 2

    report = {"pcap": args.pcap, "checks": {}, "overall": "pass"}
    for name in args.check:
        try:
            details, assertions = CHECKS[name](args.pcap, args)
            failed = [a for a in assertions if not a[1]]
            report["checks"][name] = {
                "pass": not failed,
                "details": details,
                "assertions": [{"name": a[0], "pass": a[1], "message": a[2]}
                               for a in assertions],
            }
            if failed:
                report["overall"] = "fail"
        except CheckError as exc:
            report["checks"][name] = {"pass": False, "error": str(exc)}
            report["overall"] = "fail"
        except Exception as exc:  # defensive: never crash without a report
            report["checks"][name] = {
                "pass": False, "error": "unexpected: %r" % exc}
            report["overall"] = "fail"

    indent = 2 if args.pretty else None
    print(json.dumps(report, indent=indent, sort_keys=True))
    return 0 if report["overall"] == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
