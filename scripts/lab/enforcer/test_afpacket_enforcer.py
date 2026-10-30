#!/usr/bin/env python3
import socket
import struct
import unittest

import afpacket_enforcer as enf


def udp_frame(payload, sport=45001, dport=enf.CONTROL_PORT,
              src="172.30.240.10", dst="172.30.241.10"):
    udp = struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload
    total = 20 + len(udp)
    ip = bytearray(20)
    ip[0] = 0x45
    ip[2:4] = struct.pack("!H", total)
    ip[8] = 64
    ip[9] = 17
    ip[12:16] = socket.inet_aton(src)
    ip[16:20] = socket.inet_aton(dst)
    return b"\x00" * 12 + struct.pack("!H", enf.ETH_P_IP) + bytes(ip) + udp


def quic_initial():
    # Header form=1, fixed bit=1, Initial type, version 1, two 8-byte CIDs.
    return b"\xc3\x00\x00\x00\x01\x08" + bytes(range(8)) + \
        b"\x08" + bytes(range(8, 16)) + b"\x00\x40"


class AfpacketEnforcerTest(unittest.TestCase):
    def test_quic_bootstrap_and_reverse_short_header(self):
        flows = set()
        kind, detail = enf.classify(udp_frame(quic_initial()), flows)
        self.assertEqual(kind, "quic-initial")
        self.assertEqual(len(flows), 2)
        reverse = udp_frame(b"\x40encrypted-short-header", sport=45000,
                            dport=45001, src="172.30.241.10",
                            dst="172.30.240.10")
        kind, _ = enf.classify(reverse, flows)
        self.assertEqual(kind, "quic-established")

    def test_unrelated_flow_does_not_inherit_allowance(self):
        flows = set()
        enf.classify(udp_frame(quic_initial()), flows)
        kind, _ = enf.classify(udp_frame(b"random", sport=45999), flows)
        self.assertEqual(kind, "unclassified-udp")

    def test_invalid_version_and_fixed_bit_do_not_bootstrap(self):
        flows = set()
        bad_version = bytearray(quic_initial())
        bad_version[1:5] = b"\x00\x00\x00\x02"
        self.assertEqual(enf.classify(udp_frame(bytes(bad_version)), flows)[0],
                         "unclassified-udp")
        bad_fixed = bytearray(quic_initial())
        bad_fixed[0] &= ~0x40
        self.assertEqual(enf.classify(udp_frame(bytes(bad_fixed)), flows)[0],
                         "unclassified-udp")
        self.assertFalse(flows)

    def test_policy_verdicts_are_scoped(self):
        self.assertEqual(enf.verdict("quic-v1", "quic-initial"), "ALLOW")
        self.assertEqual(enf.verdict("quic-v1", "quic-established"), "ALLOW")
        self.assertEqual(enf.verdict("quic-v1", "stun"), "DROP")
        self.assertEqual(enf.verdict("quic-stun", "stun"), "ALLOW")
        self.assertEqual(enf.verdict("quic-stun", "quic-initial"), "DROP")
        self.assertEqual(enf.verdict("off", "unclassified-udp"), "ALLOW")

    def test_malformed_frames_fail_closed(self):
        for frame in (b"", b"\x00" * 13, b"\x00" * 12 + b"\x08\x00" + b"\x45"):
            kind, _ = enf.classify(frame, set())
            self.assertEqual(kind, "malformed")
            self.assertEqual(enf.verdict("quic-v1", kind), "DROP")


if __name__ == "__main__":
    unittest.main()
