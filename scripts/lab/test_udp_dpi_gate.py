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
LEGACY_NDPI42_QUIC_OUTPUT = """1\tUDP 192.0.2.1:50000 <-> 198.51.100.2:443 [proto: 188/QUIC][Encrypted][Confidence: DPI][cat: Web/5]

Detected protocols:
    QUIC               packets: 4           bytes: 1200

Protocol statistics:
"""
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


TSHARK_ROWS = (
    "1\t0\t1700000000.000000\t100\t192.0.2.1\t\t198.51.100.2\t\t50000\t443\n"
    "2\t0\t1700000000.050000\t120\t198.51.100.2\t\t192.0.2.1\t\t443\t50000\n"
    "3\t0\t1700000000.100000\t100\t192.0.2.1\t\t198.51.100.2\t\t50000\t443\n"
    "4\t0\t1700000000.150000\t120\t198.51.100.2\t\t192.0.2.1\t\t443\t50000\n"
)


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

    def test_ndpi42_flow_without_stack_is_parsed_without_inventing_one(self):
        flows = gate.parse_flows(LEGACY_NDPI42_QUIC_OUTPUT)
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0].proto, "QUIC")
        self.assertEqual(flows[0].stack, "")
        self.assertEqual(flows[0].confidence, "DPI")
        self.assertTrue(gate.evaluate_verdict(
            "target", ["QUIC"], flows,
            gate.parse_detected_protocols(LEGACY_NDPI42_QUIC_OUTPUT)
        )[0])

    def test_detected_protocol_summary(self):
        self.assertEqual(gate.parse_detected_protocols(STUN_OUTPUT), ["STUN"])
        self.assertEqual(gate.parse_detected_protocols("no summary"), [])

    def test_ndpi42_stderr_flow_report_is_read(self):
        proc = subprocess.CompletedProcess(
            ["ndpiReader"], 0, stdout="", stderr=LEGACY_NDPI42_QUIC_OUTPUT
        )
        with patch.object(gate.subprocess, "run", return_value=proc):
            flows, detected = gate.classify_capture("ndpiReader", Path("unused.pcap"), 1)
        self.assertEqual([flow.proto for flow in flows], ["QUIC"])
        self.assertEqual(detected, ["QUIC"])

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
            return completed(command, TSHARK_ROWS)
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
                return completed(
                    command,
                    "1\t0\t1700000000.000000\t100\t192.0.2.1\t\t198.51.100.2\t\t50000\t443\n"
                    "2\t\t1700000000.050000\t20\t192.0.2.1\t\t198.51.100.2\t\t50000\t443\n",
                )
            return completed(command, STUN_OUTPUT)
        with patch.object(gate.subprocess, "run", side_effect=non_udp):
            report = gate.evaluate_manifest(self.make_manifest(), "ndpiReader", "tshark")
        self.assertFalse(report["passed"])
        self.assertIn("non-UDP", report["captures"][0]["reason"])

    def test_tool_failure_is_a_failed_check_not_a_pass(self):
        def failed_ndpi(command, **kwargs):
            if Path(command[0]).name == "tshark":
                return completed(command, TSHARK_ROWS)
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


class Schema2EvidenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)

    def tearDown(self):
        self.temp.cleanup()

    def entry(self, capture_id, session_id, role="target", **overrides):
        entry = {
            "id": capture_id,
            "session_id": session_id,
            "pcap": f"{capture_id}.pcap",
            "role": role,
            "expected": ["STUN"],
            "min_udp_packets": 4,
            "min_udp_bytes": 400,
            "min_duration_ms": 100,
            "require_bidirectional": True,
            "phase": "stable_data",
        }
        entry.update(overrides)
        (self.root / entry["pcap"]).write_bytes(capture_id.encode())
        return entry

    def manifest(self, entries):
        path = self.root / "manifest.json"
        path.write_text(json.dumps({"schema_version": 2, "captures": entries}))
        return path

    def fake_tools(self, command, **kwargs):
        name = Path(command[0]).name
        if len(command) == 2 and command[1] == "--version":
            return completed(command, f"{name} test-version\n")
        if name == "tshark":
            return completed(command, TSHARK_ROWS)
        return completed(command, STUN_OUTPUT)

    def evaluate(self, entries, fake=None):
        with patch.object(gate.subprocess, "run", side_effect=fake or self.fake_tools):
            return gate.evaluate_manifest(
                self.manifest(entries), "ndpiReader", "tshark", ndpi_revision="pinned-test"
            )

    def test_target_requires_passed_independent_positive_control(self):
        report = self.evaluate([self.entry("candidate", "s1")])
        self.assertFalse(report["passed"])
        self.assertIn("no passed independent positive control", report["captures"][0]["reason"])

        entries = [
            self.entry("candidate", "s1"),
            self.entry("reference", "s2", role="positive_control", phase="full_session"),
        ]
        report = self.evaluate(entries)
        self.assertTrue(report["passed"])
        self.assertEqual(report["toolchain"]["ndpi_revision"], "pinned-test")
        self.assertNotIn("192.0.2.", json.dumps(report))

    def test_short_and_unidirectional_streams_fail_closed(self):
        short = "1\t0\t1700000000.000000\t500\t192.0.2.1\t\t198.51.100.2\t\t50000\t443\n"

        def short_tools(command, **kwargs):
            if len(command) == 2 and command[1] == "--version":
                return completed(command, "test-version\n")
            if Path(command[0]).name == "tshark":
                return completed(command, short)
            return completed(command, STUN_OUTPUT)

        report = self.evaluate([self.entry("candidate", "s1")], short_tools)
        self.assertFalse(report["passed"])
        self.assertIn("has 1 packets", report["captures"][0]["reason"])

        one_way = "\n".join(TSHARK_ROWS.splitlines()[0::2]) + "\n"

        def one_way_tools(command, **kwargs):
            if len(command) == 2 and command[1] == "--version":
                return completed(command, "test-version\n")
            if Path(command[0]).name == "tshark":
                return completed(command, one_way)
            return completed(command, STUN_OUTPUT)

        entry = self.entry("candidate", "s1", min_udp_packets=1, min_udp_bytes=0, min_duration_ms=0)
        report = self.evaluate([entry], one_way_tools)
        self.assertFalse(report["passed"])
        self.assertIn("not bidirectional", report["captures"][0]["reason"])

    def test_schema2_target_requires_one_explicit_protocol(self):
        entry = self.entry("candidate", "s1", expected=["QUIC", "STUN"])
        with self.assertRaisesRegex(gate.ManifestError, "exactly one expected protocol"):
            gate.load_manifest(self.manifest([entry]))

    def test_schema2_requirements_and_tool_versions_are_mandatory(self):
        entry = self.entry("candidate", "s1")
        del entry["min_udp_packets"]
        with self.assertRaisesRegex(gate.ManifestError, "schema 2 requires"):
            gate.load_manifest(self.manifest([entry]))

        def broken_version(command, **kwargs):
            if len(command) == 2 and command[1] == "--version":
                return completed(command, "unsupported", returncode=2)
            return self.fake_tools(command, **kwargs)

        report = self.evaluate([self.entry("candidate", "s1")], broken_version)
        self.assertFalse(report["passed"])
        self.assertIn("--version exited with status 2", report["captures"][0]["reason"])

    def test_ndpi42_informational_version_rc_is_compatible_but_not_hidden(self):
        def ndpi42_version(command, **kwargs):
            if len(command) == 2 and command[1] == "--version" and Path(command[0]).name == "ndpiReader":
                return completed(command, "Welcome to nDPI 4.2.0\n", returncode=1)
            return self.fake_tools(command, **kwargs)

        report = self.evaluate([self.entry("candidate", "s1")], ndpi42_version)
        self.assertEqual(report["toolchain"]["ndpi_version"], "Welcome to nDPI 4.2.0")
        self.assertNotIn("--version exited", report["captures"][0]["reason"])
        self.assertIn("no passed independent positive control", report["captures"][0]["reason"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
