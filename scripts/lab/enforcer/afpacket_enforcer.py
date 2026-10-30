#!/usr/bin/env python3
"""Independent in-path userspace IPS for the disposable enforcer cell.

AF_PACKET bump-in-the-wire: binds raw packet sockets to two veth halves in
the middle network namespace and forwards Ethernet frames between them.
There is no kernel bridge and no IP address in the middle namespace, so the
only way traffic crosses between the client and server namespaces is through
this process. A DROP verdict therefore means the frame is actively discarded
by the enforcer, not by a timeout or a missing listener.

Policies:
  off        forward every frame (baseline/reference mode);
  quic-stun  allow ARP plus STUN Binding Request/Success (magic cookie
             0x2112A442) on the control port; default-deny every other UDP
             payload with an independent alert;
  quic-v1    allow ARP plus a bidirectional UDP flow bootstrapped by a
             structurally valid QUIC v1 long-header packet on the control
             port; default-deny every other UDP payload. This is a bounded
             structural flow policy, not QUIC cryptographic validation.

Every frame decision is appended to the verdicts JSONL log with a SHA-256 of
the UDP payload so drops can be correlated with client controls. Drops in
enforce mode additionally emit Suricata-fast.log-style alert lines.
"""
import argparse
import hashlib
import json
import selectors
import socket
import struct
import sys
import time
from pathlib import Path

ETH_P_ALL = 0x0003
ETH_P_IP = 0x0800
ETH_P_ARP = 0x0806
STUN_COOKIE = 0x2112A442
CONTROL_PORT = 45000
ALERT_TEXT = "NCP ENF default deny unclassified UDP"


def quic_long_header_v1(payload):
    """Conservative structural check for a QUIC v1 long header.

    It deliberately does not claim decryption or cryptographic peer validation;
    it only bootstraps the independent lab flow policy.
    """
    if len(payload) < 7 or payload[0] & 0xC0 != 0xC0:
        return False
    if payload[1:5] != b"\x00\x00\x00\x01":
        return False
    dcid_len = payload[5]
    if dcid_len > 20 or len(payload) < 6 + dcid_len + 1:
        return False
    scid_offset = 6 + dcid_len
    scid_len = payload[scid_offset]
    return scid_len <= 20 and len(payload) >= scid_offset + 1 + scid_len + 1


def flow_key(detail, reverse=False):
    if reverse:
        return (detail["dst"], detail["dport"],
                detail["src"], detail["sport"])
    return (detail["src"], detail["sport"],
            detail["dst"], detail["dport"])


def classify(frame, quic_flows=None):
    """Return (kind, detail) for an Ethernet frame."""
    if len(frame) < 14:
        return "malformed", {}
    ethertype = struct.unpack("!H", frame[12:14])[0]
    if ethertype == ETH_P_ARP:
        return "arp", {}
    if ethertype != ETH_P_IP:
        return "non-ip", {"ethertype": ethertype}
    if len(frame) < 34:
        return "malformed", {}
    ihl = (frame[14] & 0x0F) * 4
    if ihl < 20 or len(frame) < 14 + ihl:
        return "malformed", {}
    proto = frame[23]
    src = socket.inet_ntoa(frame[26:30])
    dst = socket.inet_ntoa(frame[30:34])
    detail = {"src": src, "dst": dst, "proto": proto}
    if proto != 17:
        return "non-udp", detail
    udp_off = 14 + ihl
    if len(frame) < udp_off + 8:
        return "malformed", detail
    sport, dport, ulen = struct.unpack("!HHH", frame[udp_off:udp_off + 6])
    if ulen < 8 or len(frame) < udp_off + ulen:
        return "malformed", detail
    payload = frame[udp_off + 8:udp_off + ulen]
    detail.update({"sport": sport, "dport": dport,
                   "payload_sha256": hashlib.sha256(payload).hexdigest(),
                   "payload_len": len(payload)})
    if sport == CONTROL_PORT or dport == CONTROL_PORT:
        if (len(payload) >= 20
                and struct.unpack("!H", payload[:2])[0] & 0x3FFF in (0x0001, 0x0101)
                and struct.unpack("!I", payload[4:8])[0] == STUN_COOKIE):
            return "stun", detail
        if quic_flows is not None:
            if flow_key(detail) in quic_flows:
                return "quic-established", detail
            if quic_long_header_v1(payload):
                if len(quic_flows) < 2048:  # at most 1024 bidirectional flows
                    quic_flows.add(flow_key(detail))
                    quic_flows.add(flow_key(detail, reverse=True))
                    return "quic-initial", detail
        return "unclassified-udp", detail
    return "udp-other-port", detail


def verdict(policy, kind):
    if policy == "off":
        return "ALLOW"
    if kind == "arp":
        return "ALLOW"
    if policy == "quic-stun" and kind == "stun":
        return "ALLOW"
    if policy == "quic-v1" and kind in ("quic-initial", "quic-established"):
        return "ALLOW"
    return "DROP"


def fix_udp_checksum(frame):
    """Recompute the UDP checksum of an IPv4/UDP frame in place.

    Frames tapped on veth pairs may carry a CHECKSUM_PARTIAL UDP checksum
    (TX offload). The peer namespace's kernel drops those on receipt, so an
    in-path forwarder must finalize the checksum before re-injecting.
    """
    ihl = (frame[14] & 0x0F) * 4
    udp_off = 14 + ihl
    ulen = struct.unpack("!H", frame[udp_off + 4:udp_off + 6])[0]
    udp = bytearray(frame[udp_off:udp_off + ulen])
    udp[6:8] = b"\x00\x00"
    pseudo = frame[26:34] + struct.pack("!BBH", 0, 17, ulen)
    blob = bytes(pseudo) + bytes(udp)
    if len(blob) % 2:
        blob += b"\x00"
    total = 0
    for i in range(0, len(blob), 2):
        total += (blob[i] << 8) | blob[i + 1]
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    csum = (~total) & 0xFFFF or 0xFFFF
    frame[udp_off + 6:udp_off + 8] = struct.pack("!H", csum)
    return frame


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--if-a", required=True)
    parser.add_argument("--if-b", required=True)
    parser.add_argument("--policy", choices=("off", "quic-stun", "quic-v1"),
                        required=True)
    parser.add_argument("--verdicts", required=True)
    parser.add_argument("--alerts", required=True)
    args = parser.parse_args()

    socks = {}
    for name in (args.if_a, args.if_b):
        s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(ETH_P_ALL))
        s.bind((name, 0))
        s.setblocking(False)
        socks[s.fileno()] = (s, name)
    peer = {args.if_a: args.if_b, args.if_b: args.if_a}
    by_name = {name: s for s, name in socks.values()}

    sel = selectors.DefaultSelector()
    for fd in socks:
        sel.register(fd, selectors.EVENT_READ)

    verdicts_path = Path(args.verdicts)
    alerts_path = Path(args.alerts)
    stats = {"allowed": 0, "dropped": 0}
    quic_flows = set()
    with verdicts_path.open("a", encoding="utf-8") as vlog, \
            alerts_path.open("a", encoding="utf-8") as alog:
        print("Engine started.", flush=True)
        while True:
            for key, _ in sel.select():
                sock, iname = socks[key.fd]
                try:
                    frame, addr = sock.recvfrom(65535)
                except BlockingIOError:
                    continue
                # addr = (ifname, proto, pkttype, hatype, hwaddr); skip the
                # PACKET_OUTGOING copy of frames this process injected.
                if addr[2] == socket.PACKET_OUTGOING:
                    continue
                kind, detail = classify(frame, quic_flows)
                decision = verdict(args.policy, kind)
                is_udp = detail.get("proto") == 17 and \
                    len(frame) >= 14 + (frame[14] & 0x0F) * 4 + 8
                record = {"ts": round(time.time(), 6), "iface": iname,
                          "policy": args.policy, "kind": kind,
                          "verdict": decision,
                          "checksum_finalized": bool(is_udp), **detail}
                vlog.write(json.dumps(record) + "\n")
                vlog.flush()
                if decision == "ALLOW":
                    stats["allowed"] += 1
                    out = fix_udp_checksum(bytearray(frame)) if is_udp else frame
                    by_name[peer[iname]].send(bytes(out))
                else:
                    stats["dropped"] += 1
                    if detail.get("proto") == 17:
                        proto = "UDP"
                        text = ALERT_TEXT
                        ep = f"{detail['src']}:{detail['sport']} -> " \
                             f"{detail['dst']}:{detail['dport']}"
                    elif "ethertype" in detail and "src" not in detail:
                        proto = "L2"
                        text = "NCP ENF default deny non-IP traffic"
                        ep = f"ethertype 0x{detail['ethertype']:04x}"
                    else:
                        proto = str(detail.get("proto", "?"))
                        text = "NCP ENF default deny non-UDP traffic"
                        ep = f"{detail.get('src', '?')} -> {detail.get('dst', '?')}"
                    alog.write(
                        f"{time.strftime('%m/%d/%Y-%H:%M:%S')}  [**] "
                        f"[1:4000001:1] {text} [**] [Classification: "
                        f"default-deny] [Priority: 1] {{{proto}}} {ep}\n")
                    alog.flush()


if __name__ == "__main__":
    sys.exit(main())
