#!/usr/bin/env python3
"""Hermetic regression tests for udp_dpi_gate.py (no nDPI/tshark required)."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
import udp_dpi_gate as gate


STUN_OUTPUT = """1\t[proto: 140.252/STUN][Stack: STUN][ClearText][Confidence: DPI]

Detected protocols:
    STUN               packets: 4           bytes: 1200

Protocol statistics:
"""
QUIC_OUTPUT = STUN_OUTPUT.replace("STUN", "QUIC")
UNKNOWN_OUTPUT = """1\t[proto: 0/Unknown][Stack: Unknown][ClearText][Confidence: Unknown]

Detected protocols:
    Unknown            packets: 4           bytes: 1200

Protocol statistics:
"""
WIREGUARD_OUTPUT = """1\t[proto: 175/WireGuard][Stack: WireGuard][Encrypted][Confidence: DPI]

Detected protocols:
    WireGuard          packets: 4           bytes: 1200

Protocol statistics:
"""
DNS_OUTPUT = """1\t[proto: 5/DNS][Stack: DNS][ClearText][Confidence: DPI]

Detected protocols:
    DNS                packets: 4           bytes: 1200

Protocol statistics:
"""


def completed(command, stdout="", returncode=0):
    return subprocess.CompletedProcess(command, returncode, stdout, "")


class ParserTests(unittest.TestCase):
    def test_flow_parser_ignores_addresses_and_reads_risks(self):
        text = (
            "7 192.0.2.1:50000 <-> 198.51.100.2:443 "
            "[proto: 140/STUN][Stack: STUN][ClearText][Confidence: DPI]"
            "[Risk: ** Anonymous Subscriber **]"
        )
        flows = gate.parse_flows(text)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].proto, "STUN")
        self.assertEqual(flows[0].confidence, "DPI")
        self.assertEqual(flows[0].risks, ("Anonymous Subscriber",))
        self.assertTrue(gate.is_vpn(flows[0]))

    def test_detected_protocol_summary(self):
        self.assertEqual(gate.parse_detected_protocols(STUN_OUTPUT), ["STUN"])
        self.assertEqual(gate.parse_detected_protocols("no summary"), [])

    def test_protocol_token_does_not_match_substring(self):
        flow = gate.Flow("NOTQUIC", "NOTQUIC", "DPI", ())
        self.assertFalse(gate.has_any_token(flow, ["QUIC"]))


class VerdictTests(unittest.TestCase):
    def verdict(self, role, output, expected=None):
        return gate.evaluate_verdict(
            role, expected or ["STUN"], gate.parse_flows(output),
            gate.parse_detected_protocols(output)
        )

    def test_target_accepts_only_expected_dpi_classification(self):
        passed, _ = self.verdict("target", STUN_OUTPUT)
        self.assertTrue(passed)
        passed, reason = self.verdict("target", QUIC_OUTPUT)
        self.assertFalse(passed)
        self.assertIn("not every flow", reason)

    def test_target_rejects_low_confidence_match(self):
        output = STUN_OUTPUT.replace("Confidence: DPI", "Confidence: Match by port")
        passed, reason = self.verdict("target", output)
        self.assertFalse(passed)
        self.assertIn("DPI confidence", reason)

    def test_target_rejects_known_vpn(self):
        passed, reason = self.verdict("target", WIREGUARD_OUTPUT, ["WireGuard"])
        self.assertFalse(passed)
        self.assertIn("known VPN", reason)

    def test_target_rejects_extra_summary_protocol(self):
        # Add a second summary row; a flow-only assertion would miss this leak.
        output = STUN_OUTPUT.replace(
            "\n\nProtocol statistics:", "\n    DNS packets: 1\n\nProtocol statistics:"
        )
        passed, reason = self.verdict("target", output)
        self.assertFalse(passed)
        self.assertIn("unexpected protocols", reason)

    def test_negative_control_accepts_unknown_or_vpn(self):
        self.assertTrue(self.verdict("negative_control", UNKNOWN_OUTPUT)[0])
        self.assertTrue(self.verdict("negative_control", WIREGUARD_OUTPUT)[0])

    def test_negative_control_rejects_target_or_other_benign_protocol(self):
        self.assertFalse(self.verdict("negative_control", STUN_OUTPUT)[0])
        passed, reason = self.verdict("negative_control", DNS_OUTPUT)
        self.assertFalse(passed)
        self.assertIn("another recognised benign", reason)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def add_capture(self, name, content):
        path = self.root / name
        path.write_bytes(content)
        return name

    def write_manifest(self, captures):
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"schema_version": 1, "captures": captures}), encoding="utf-8")
        return path

    def entry(self, capture_id, session_id, pcap, role="target", expected=None):
        return {
            "id": capture_id, "session_id": session_id, "pcap": pcap,
            "role": role, "expected": expected or ["STUN"],
        }

    def test_rejects_duplicate_session_and_capture_ids(self):
        pcap = self.add_capture("a.pcap", b"a")
        path = self.write_manifest([
            self.entry("a", "same-session", pcap),
            self.entry("b", "same-session", pcap),
        ])
        with self.assertRaisesRegex(gate.ManifestError, "session-disjoint"):
            gate.load_manifest(path)
        path = self.write_manifest([
            self.entry("a", "s1", pcap), self.entry("a", "s2", pcap),
        ])
        with self.assertRaisesRegex(gate.ManifestError, "duplicate capture id"):
            gate.load_manifest(path)

    def test_rejects_path_escape_and_duplicate_json_keys(self):
        outside = Path(self.temp.name).parent / "outside-dynam-gate.pcap"
        outside.write_bytes(b"outside")
        self.addCleanup(outside.unlink, missing_ok=True)
        path = self.write_manifest([self.entry("a", "s1", "../outside-dynam-gate.pcap")])
        with self.assertRaisesRegex(gate.ManifestError, "escapes"):
            gate.load_manifest(path)
        path.write_text(
            '{"schema_version":1,"schema_version":1,"captures":[]}', encoding="utf-8"
        )
        with self.assertRaisesRegex(gate.ManifestError, "duplicate JSON key"):
            gate.load_manifest(path)

    def test_rejects_duplicate_capture_bytes(self):
        a = self.add_capture("a.pcap", b"same bytes")
        b = self.add_capture("b.pcap", b"same bytes")
        path = self.write_manifest([self.entry("a", "s1", a), self.entry("b", "s2", b)])
        with self.assertRaisesRegex(gate.ManifestError, "duplicate capture bytes"):
            gate.evaluate_manifest(path, "ndpi", "tshark")


class EvaluationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def make_manifest(self, second_role="negative_control"):
        (self.root / "target.pcap").write_bytes(b"target capture")
        (self.root / "control.pcap").write_bytes(b"control capture")
        path = self.root / "manifest.json"
        path.write_text(json.dumps({
            "schema_version": 1,
            "captures": [
                {"id": "target", "session_id": "session-a", "pcap": "target.pcap",
                 "role": "target", "expected": ["STUN"]},
                {"id": "control", "session_id": "session-b", "pcap": "control.pcap",
                 "role": second_role, "expected": ["STUN"]},
            ],
        }), encoding="utf-8")
        return path

    def fake_tools(self, command, **kwargs):
        if Path(command[0]).name == "tshark":
            return completed(command, "1\t0\n2\t0\n")
        ndpi_output = STUN_OUTPUT if any("target.pcap" in arg for arg in command) else UNKNOWN_OUTPUT
        return completed(command, ndpi_output)

    def test_end_to_end_report_passes_with_independent_controls(self):
        with patch.object(gate.subprocess, "run", side_effect=self.fake_tools):
            report = gate.evaluate_manifest(self.make_manifest(), "ndpiReader", "tshark")
        self.assertTrue(report["passed"])
        self.assertEqual(report["passed_count"], 2)
        self.assertEqual(report["failed_count"], 0)
        rendered = json.dumps(report)
        self.assertNotIn("192.0.2.", rendered)
        self.assertNotIn("target.pcap", rendered)

    def test_non_udp_or_empty_capture_fails_closed(self):
        def non_udp(command, **kwargs):
            if Path(command[0]).name == "tshark":
                return completed(command, "1\t0\n2\t\n")
            return completed(command, STUN_OUTPUT)
        with patch.object(gate.subprocess, "run", side_effect=non_udp):
            report = gate.evaluate_manifest(self.make_manifest(), "ndpiReader", "tshark")
        self.assertFalse(report["passed"])
        self.assertIn("non-UDP", report["captures"][0]["reason"])

    def test_tool_failure_is_a_failed_check_not_a_pass(self):
        def failed_ndpi(command, **kwargs):
            if Path(command[0]).name == "tshark":
                return completed(command, "1\t0\n")
            return completed(command, "tool diagnostic", returncode=3)
        with patch.object(gate.subprocess, "run", side_effect=failed_ndpi):
            report = gate.evaluate_manifest(self.make_manifest(), "ndpiReader", "tshark")
        self.assertFalse(report["passed"])
        self.assertEqual(report["failed_count"], 2)
        self.assertIn("status 3", report["captures"][0]["reason"])

    def test_cli_exit_codes_and_output_report(self):
        output = self.root / "report.json"
        with patch.object(gate.subprocess, "run", side_effect=self.fake_tools):
            rc = gate.main([
                str(self.make_manifest()), "--ndpi", "ndpiReader", "--tshark", "tshark",
                "--output", str(output),
            ])
        self.assertEqual(rc, 0)
        self.assertTrue(json.loads(output.read_text(encoding="utf-8"))["passed"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
