#!/usr/bin/env python3
"""dpi-emu.py — userspace DPI emulator with TCP reassembly (NFQUEUE + scapy).

Runs on the dpi-server container of the Dynam lab. Client->server TCP
segments (dport 443/80) are diverted by iptables into NFQUEUE; per flow the
segments are reassembled in userspace (Reassembler) and the assembled byte
stream is parsed for a TLS ClientHello SNI / HTTP Host header. Verdicts:

  * blocked name found          -> forged RST both ways + NF_DROP (block)
  * name found, not blocked     -> accept held packets, fast-path (allow)
  * BUFFER_LIMIT reached w/o SNI/Host -> allow ("DPI gave up on the buffer")
  * OOO_POLICY=strict anomaly   -> treated as block (paranoid DPI)

Limitations (documented in SPEC): packets with a bad TCP checksum are dropped
by the kernel before NFQUEUE sees them, so badsum fakes are invisible here;
TTL fakes are not modelled in the 2-node stand (1 hop).

Pure logic (Reassembler, parse_tls_sni, parse_http_host) is importable
without root/NFQUEUE for unit tests.
"""
import argparse
import json
import os
import signal
import sys
import threading
import time

# ---------------------------------------------------------------------------
# Reassembler — pure TCP reassembly logic, independently unit-testable.
# ---------------------------------------------------------------------------

OOO_STRICT = "strict"
OOO_FIRST = "permissive-first"
OOO_LAST = "permissive-last"


class Reassembler:
    """Reassembles one directional TCP byte stream (C->S).

    feed(seq, payload) per segment; assembled() returns the contiguous stream
    starting at the first segment's seq. Overlap handling depends on policy:

      strict          — any overlap with DIFFERENT payload bytes -> anomaly;
                        more than `max_ooo` out-of-order segments buffered ->
                        anomaly.
      permissive-first— on overlap the bytes received FIRST win (old DPI).
      permissive-last — on overlap the bytes received LAST win (Linux stack).
    """

    def __init__(self, buffer_limit=16384, ooo_policy=OOO_FIRST, max_ooo=2):
        if ooo_policy not in (OOO_STRICT, OOO_FIRST, OOO_LAST):
            raise ValueError("bad ooo_policy: %r" % ooo_policy)
        self.buffer_limit = int(buffer_limit)
        self.ooo_policy = ooo_policy
        self.max_ooo = int(max_ooo)
        self.base = None          # absolute seq of byte 0 of the stream
        self.data = bytearray()   # contiguous assembled bytes from base
        self.pending = []         # [(seq, payload)] out-of-order, receipt order
        self.anomaly = None       # str reason once detected

    # -- helpers ------------------------------------------------------------
    @property
    def next_seq(self):
        return None if self.base is None else self.base + len(self.data)

    @property
    def limit_reached(self):
        return len(self.data) >= self.buffer_limit

    def assembled(self):
        return bytes(self.data)

    # -- core ---------------------------------------------------------------
    def feed(self, seq, payload):
        """Feed one segment. Returns True if the contiguous stream grew."""
        if not payload or self.anomaly:
            return False
        if self.base is None:
            self.base = seq
        self._insert(seq, bytes(payload))
        self._drain()
        if (self.ooo_policy == OOO_STRICT and not self.anomaly
                and len(self.pending) > self.max_ooo):
            self.anomaly = "ooo-segments-exceeded(%d>%d)" % (
                len(self.pending), self.max_ooo)
        return True

    def _insert(self, seq, payload):
        """Insert a segment that touches or extends the contiguous region."""
        end = seq + len(payload)
        nxt = self.next_seq
        if end <= self.base:
            # fully retransmitted territory
            self._check_overlap(seq, payload)
            return
        if seq < nxt:
            # overlapping the assembled region
            off = seq - self.base
            old = bytes(self.data[off:off + (min(end, nxt) - seq)])
            new = payload[:min(end, nxt) - seq]
            if old != new:
                if self.ooo_policy == OOO_STRICT:
                    self.anomaly = "overlap-diff@%d" % seq
                    return
                if self.ooo_policy == OOO_LAST:
                    # last received wins: rewrite the overlapped tail
                    del self.data[off:]
                    self.data += payload
                    return
                # permissive-first: keep old bytes, append only the new tail
                self.data += payload[nxt - seq:]
                return
            # identical overlap: just append the extension
            self.data += payload[nxt - seq:]
            return
        if seq == nxt:
            self.data += payload
            return
        # gap: out-of-order, park it
        self.pending.append((seq, payload))

    def _check_overlap(self, seq, payload):
        """Fully-covered retransmission: strict verifies byte equality."""
        off = seq - self.base
        old = bytes(self.data[off:off + len(payload)])
        if old != payload and self.ooo_policy == OOO_STRICT:
            self.anomaly = "retransmit-diff@%d" % seq

    def _drain(self):
        """Consume parked segments that now touch the contiguous region."""
        progressed = True
        while progressed and not self.anomaly:
            progressed = False
            for i, (seq, payload) in enumerate(self.pending):
                if seq + len(payload) <= self.base:
                    self.pending.pop(i)
                    progressed = True
                    break
                if seq <= self.next_seq:
                    self.pending.pop(i)
                    self._insert(seq, payload)
                    progressed = True
                    break


# ---------------------------------------------------------------------------
# TLS ClientHello SNI / HTTP Host parsing from an assembled byte stream.
# ---------------------------------------------------------------------------

def parse_tls_sni(buf):
    """Return the server_name from a TLS ClientHello byte stream, else None.

    Handles ClientHello split across several TLS records and across TCP
    segments (buf is the reassembled stream; may be a prefix — returns None
    until enough bytes are present).
    """
    if len(buf) < 5 or buf[0] != 0x16:      # not a handshake record
        return None
    pos = 0
    hs = bytearray()
    try:
        while True:
            if pos + 5 > len(buf):
                return None                 # need more bytes
            if buf[pos] != 0x16:
                return None
            rlen = int.from_bytes(buf[pos + 3:pos + 5], "big")
            if pos + 5 + rlen > len(buf):
                return None                 # record not complete yet
            hs += buf[pos + 5:pos + 5 + rlen]
            pos += 5 + rlen
            if len(hs) >= 4:
                hlen = int.from_bytes(hs[1:4], "big")
                if len(hs) >= 4 + hlen:
                    break
        if hs[0] != 0x01:                   # not a ClientHello
            return None
        return _parse_client_hello(bytes(hs[4:4 + hlen]))
    except (IndexError, ValueError):
        return None


def tls_clienthello_complete(buf):
    """True when the buffer holds the FULL first handshake message (a DPI
    would stop waiting for more bytes at this point, SNI or not)."""
    if len(buf) < 5 or buf[0] != 0x16:
        return False
    pos = 0
    hs_len = 0
    try:
        while True:
            if pos + 5 > len(buf):
                return False
            if buf[pos] != 0x16:
                return False
            rlen = int.from_bytes(buf[pos + 3:pos + 5], "big")
            if pos + 5 + rlen > len(buf):
                return False
            hs_len += rlen
            pos += 5 + rlen
            if hs_len >= 4:
                # handshake header lives at buf[5:9] of the first record
                hlen = int.from_bytes(buf[6:9], "big")
                if hs_len >= 4 + hlen:
                    return True
    except (IndexError, ValueError):
        return False


def http_headers_complete(buf):
    return b"\r\n\r\n" in buf[:4096]


def _parse_client_hello(body):
    p = 0
    p += 2                                  # client_version
    p += 32                                 # random
    sid_len = body[p]; p += 1 + sid_len
    cs_len = int.from_bytes(body[p:p + 2], "big"); p += 2 + cs_len
    comp_len = body[p]; p += 1 + comp_len
    if p + 2 > len(body):
        return None                         # no extensions
    ext_total = int.from_bytes(body[p:p + 2], "big"); p += 2
    ext_end = min(len(body), p + ext_total)
    while p + 4 <= ext_end:
        etype = int.from_bytes(body[p:p + 2], "big")
        elen = int.from_bytes(body[p + 2:p + 4], "big")
        p += 4
        if etype == 0x0000:                 # server_name
            q = p + 2                       # skip server_name_list length
            while q + 3 <= p + elen:
                ntype = body[q]
                nlen = int.from_bytes(body[q + 1:q + 3], "big")
                q += 3
                if ntype == 0:
                    return body[q:q + nlen].decode("ascii", "replace")
                q += nlen
        p += elen
    return None


_HTTP_METHODS = (b"GET ", b"POST ", b"HEAD ", b"PUT ", b"DELETE ", b"OPTIONS ",
                 b"PATCH ", b"CONNECT ", b"TRACE ")


def parse_http_host(buf):
    """Return the Host header value (no port) from an HTTP request stream."""
    head = buf[:4096]
    if not any(head.startswith(m) for m in _HTTP_METHODS):
        return None
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"host:"):
            host = line[5:].strip().split(b":")[0]
            return host.decode("ascii", "replace") or None
        if line == b"":
            break
    return None


def stream_protocol(buf):
    """Best-effort protocol guess: 'tls', 'http', 'unknown' or None (too early)."""
    if not buf:
        return None
    if buf[0] == 0x16:
        return "tls"
    if len(buf) < 4:
        # could still become either
        return None if any(m.startswith(buf) for m in _HTTP_METHODS) else "unknown"
    if any(buf.startswith(m) for m in _HTTP_METHODS):
        return "http"
    return "unknown"


# ---------------------------------------------------------------------------
# NFQUEUE DPI engine (requires root + netfilterqueue).
# ---------------------------------------------------------------------------

class Flow:
    __slots__ = ("key", "reasm", "state", "held", "sni", "last_seen",
                 "proto", "verdict_name")

    def __init__(self, key, reasm):
        self.key = key                # (src, sport, dst, dport)
        self.reasm = reasm
        self.state = "inspect"        # inspect | allow
        self.held = []                # [(pkt, seq, payload)] awaiting verdict
        self.sni = None
        self.proto = None
        self.last_seen = time.time()


class DpiEmu:
    def __init__(self, model, buffer_limit, ooo_policy, blocked, queue_num):
        self.model = model
        self.buffer_limit = buffer_limit
        self.ooo_policy = ooo_policy
        self.blocked = {d.strip().lower() for d in blocked if d.strip()}
        self.queue_num = queue_num
        self.flows = {}
        self.lock = threading.Lock()
        self.running = True
        self._scapy = None

    # -- logging ------------------------------------------------------------
    def log(self, event, flow_key=None, reason="", sni=None):
        rec = {
            "ts": round(time.time(), 3),
            "flow": ("%s:%s>%s:%s" % flow_key) if flow_key else None,
            "event": event,
            "reason": reason,
            "model": self.model,
            "buffer_limit": self.buffer_limit,
            "ooo_policy": self.ooo_policy,
            "sni": sni,
        }
        sys.stdout.write(json.dumps(rec) + "\n")
        sys.stdout.flush()

    # -- RST injection ------------------------------------------------------
    def _inject_rst(self, ip_src, ip_dst, sport, dport, seq, ack):
        # Use a genuine kernel raw IP socket (AF_INET/IPPROTO_RAW), NOT
        # scapy's conf.L3socket — on Linux the latter is a PF_PACKET
        # L3PacketSocket that does its own L2 MAC resolution (blocking ARP
        # stalls, broadcast-MAC fallback) and pushes frames straight onto the
        # bridge even when dst is the LOCAL server IP (they never come back).
        # With a kernel raw socket the kernel routes: dst=local server IP is
        # delivered via loopback (traverses INPUT -> NFQUEUE -> accept, which
        # is fine), dst=client goes out eth0 with proper kernel ARP.
        if self._scapy is None:
            import socket as _socket
            from scapy.all import IP, TCP, conf
            conf.verb = 0
            rsock = _socket.socket(_socket.AF_INET, _socket.SOCK_RAW,
                                   _socket.IPPROTO_RAW)
            self._scapy = (IP, TCP, rsock)
        IP, TCP, rsock = self._scapy
        try:
            pkt = IP(src=ip_src, dst=ip_dst) / TCP(
                sport=sport, dport=dport, flags="R", seq=seq, ack=ack)
            rsock.sendto(bytes(pkt), (ip_dst, 0))
        except Exception as exc:  # never die on injection failure
            self.log("error", reason="rst-inject: %s" % exc)

    def _block_flow(self, flow, reason):
        """Drop held packets, RST both directions, forget the flow.

        RFC 5961-conformant RST needs the exact rcv_nxt of each side. While
        inspecting we hold ALL data segments, so: server rcv_nxt == seq of the
        first held segment; client rcv_nxt == ack of any held data segment
        (the client has acked nothing beyond the SYN-ACK yet).
        """
        first_seq = flow.held[0][1] if flow.held else None
        last_ack = flow.held[-1][2] if flow.held else None
        for pkt, _seq, _ack, _payload in flow.held:
            pkt.drop()
        flow.held.clear()
        src, sport, dst, dport = flow.key
        if first_seq is not None:
            # kill the server-side socket (client->server direction)
            self._inject_rst(src, dst, sport, dport, first_seq, 0)
            # kill the client-side socket (server->client direction)
            self._inject_rst(dst, src, dport, sport, last_ack, 0)
        self.flows.pop(flow.key, None)
        self.log("block", flow.key, reason, flow.sni)

    def _allow_flow(self, flow, reason):
        for pkt, _seq, _ack, _payload in flow.held:
            pkt.accept()
        flow.held.clear()
        flow.state = "allow"
        self.log("allow", flow.key, reason, flow.sni)

    # -- packet callback ----------------------------------------------------
    def handle(self, pkt):
        from scapy.all import IP, TCP
        try:
            ip = IP(pkt.get_payload())
        except Exception:
            pkt.accept()
            return
        if not ip.haslayer(TCP):
            pkt.accept()
            return
        tcp = ip[TCP]
        key = (ip.src, tcp.sport, ip.dst, tcp.dport)
        payload = bytes(tcp.payload)
        flags = int(tcp.flags)

        with self.lock:
            flow = self.flows.get(key)

            # fast-path
            if flow is not None and flow.state == "allow":
                flow.last_seen = time.time()
                pkt.accept()
                if flags & 0x05:  # FIN/RST -> forget
                    self.flows.pop(key, None)
                return

            # RST for an inspecting/unknown flow: pass + cleanup
            if flags & 0x04:
                if flow is not None:
                    for hpkt, _s, _a, _p in flow.held:
                        hpkt.accept()
                    self.flows.pop(key, None)
                pkt.accept()
                return

            if flow is None:
                flow = Flow(key, Reassembler(self.buffer_limit, self.ooo_policy))
                self.flows[key] = flow
            flow.last_seen = time.time()

            if not payload:
                # SYN / pure ACK: pass through, do not advance reassembly
                pkt.accept()
                if flags & 0x01:  # FIN on empty flow
                    for hpkt, _s, _a, _p in flow.held:
                        hpkt.accept()
                    self.flows.pop(key, None)
                return

            pkt.retain()
            flow.held.append((pkt, tcp.seq, tcp.ack, payload))
            flow.reasm.feed(tcp.seq, payload)

            if flow.reasm.anomaly:
                flow.sni = (parse_tls_sni(flow.reasm.assembled())
                            or parse_http_host(flow.reasm.assembled()))
                self.log("anomaly", key, flow.reasm.anomaly, flow.sni)
                self._block_flow(flow, "anomaly:" + flow.reasm.anomaly)
                return

            stream = flow.reasm.assembled()
            proto = flow.proto or stream_protocol(stream)
            flow.proto = proto
            name = None
            if proto == "tls":
                name = parse_tls_sni(stream)
                if not name and tls_clienthello_complete(stream):
                    self._allow_flow(flow, "no-sni-in-clienthello")
                    return
            elif proto == "http":
                name = parse_http_host(stream)
                if not name and http_headers_complete(stream):
                    self._allow_flow(flow, "no-host-header")
                    return
            elif proto == "unknown":
                self._allow_flow(flow, "unknown-protocol")
                return

            if name:
                flow.sni = name
                if name.lower() in self.blocked or any(
                        name.lower().endswith("." + b) for b in self.blocked):
                    self._block_flow(flow, "blocked-domain:%s" % name)
                else:
                    self._allow_flow(flow, "sni-ok:%s" % name)
                return

            if flow.reasm.limit_reached:
                self._allow_flow(flow, "buffer-limit-reached-no-sni")
                return

            if flags & 0x01:  # FIN while still inspecting
                self._allow_flow(flow, "fin-before-verdict")
                self.flows.pop(key, None)

    # -- housekeeping -------------------------------------------------------
    def sweeper(self):
        while self.running:
            time.sleep(10)
            now = time.time()
            with self.lock:
                for key, flow in list(self.flows.items()):
                    if now - flow.last_seen > 60:
                        for hpkt, _s, _a, _p in flow.held:
                            try:
                                hpkt.accept()
                            except Exception:
                                pass
                        self.flows.pop(key, None)
                        self.log("expire", key, "idle-timeout", flow.sni)

    def run(self):
        from netfilterqueue import NetfilterQueue
        nfq = NetfilterQueue()
        nfq.bind(self.queue_num, self.handle)
        t = threading.Thread(target=self.sweeper, daemon=True)
        t.start()
        self.log("start", reason="queue=%d" % self.queue_num)

        def _term(_sig, _frm):
            self.running = False
            try:
                nfq.unbind()
            except Exception:
                pass
            os._exit(0)

        signal.signal(signal.SIGTERM, _term)
        signal.signal(signal.SIGINT, _term)
        try:
            nfq.run()
        except KeyboardInterrupt:
            pass
        finally:
            self.running = False
            try:
                nfq.unbind()
            except Exception:
                pass


def main(argv=None):
    p = argparse.ArgumentParser(description="DPI emulator with TCP reassembly")
    p.add_argument("--model", default=os.environ.get("DPI_MODEL", "reassemble"),
                   choices=["string", "reassemble"],
                   help="'string' = legacy kernel iptables model; the emulator "
                        "is a no-op and exits immediately")
    p.add_argument("--buffer-limit", type=int,
                   default=int(os.environ.get("BUFFER_LIMIT", "16384")))
    p.add_argument("--ooo", dest="ooo_policy",
                   default=os.environ.get("OOO_POLICY", OOO_FIRST),
                   choices=[OOO_STRICT, OOO_FIRST, OOO_LAST])
    p.add_argument("--blocked",
                   default=os.environ.get("BLOCKED_DOMAINS",
                                          "forbidden.example,blocked.example"),
                   help="comma-separated blocked domains")
    p.add_argument("--queue", type=int,
                   default=int(os.environ.get("NFQUEUE_NUM", "0")))
    args = p.parse_args(argv)

    if args.model == "string":
        # Legacy model is pure kernel iptables (see dpi-server-2node.sh);
        # no userspace emulator needed.
        print(json.dumps({"ts": round(time.time(), 3), "event": "noop",
                          "reason": "model=string is kernel iptables only",
                          "model": "string"}))
        return 0

    emu = DpiEmu(args.model, args.buffer_limit, args.ooo_policy,
                 args.blocked.split(","), args.queue)
    emu.run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
