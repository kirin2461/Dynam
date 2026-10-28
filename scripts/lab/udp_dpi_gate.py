#!/usr/bin/env python3
"""Independent nDPI evidence gate for Dynam UDP/mimicry captures.

The gate deliberately evaluates whole captures with external tools. It does not
trust Dynam's own traffic profiles, ports, or protocol names. Reports contain
verdicts and capture hashes, not IP addresses or packet payloads.

Exit codes: 0 = every capture passed, 1 = evidence check failed,
            2 = invalid manifest, path, or capture set.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


SCHEMA_VERSION = 1
FLOW_RE = re.compile(
    r"\[proto:\s*[0-9.]+/([^\]]+)\]"
    r"\[Stack:\s*([^\]]+)\].*?"
    r"\[(?:Encrypted|ClearText)\]\[Confidence:\s*([^\]]+)\]"
)
RISK_RE = re.compile(r"\[Risk:\s*([^\]]+)\]")
RISK_NAME_RE = re.compile(r"\*\*\s*([^*]+?)\s*\*\*")
VPN_TOKENS = (
    "VPN", "OPENVPN", "WIREGUARD", "SOFTETHER", "NORDVPN",
    "EXPRESSVPN", "HOTSPOT SHIELD", "TOR", "OBFUSCATED",
    "ANONYMOUS SUBSCRIBER",
)


class ManifestError(ValueError):
    """The capture manifest is unsafe or internally inconsistent."""


@dataclass(frozen=True)
class Flow:
    proto: str
    stack: str
    confidence: str
    risks: tuple[str, ...]

    @property
    def blob(self) -> str:
        return f"{self.proto} {self.stack}".upper()

    def public(self) -> dict[str, Any]:
        return {
            "protocol": self.proto,
            "stack": self.stack,
            "confidence": self.confidence,
            "risks": list(self.risks),
        }


def token_present(text: str, token: str) -> bool:
    return re.search(
        rf"(?<![A-Z0-9]){re.escape(token.upper())}(?![A-Z0-9])", text.upper()
    ) is not None


def has_any_token(flow: Flow, tokens: list[str]) -> bool:
    return any(token_present(flow.blob, token) for token in tokens)


def is_unknown(flow: Flow) -> bool:
    return flow.proto.strip().upper() == "UNKNOWN" or flow.stack.strip().upper() == "UNKNOWN"


def is_vpn(flow: Flow) -> bool:
    blob = f"{flow.blob} {' '.join(flow.risks)}"
    return any(token_present(blob, token) for token in VPN_TOKENS)


def parse_flows(text: str) -> list[Flow]:
    flows: list[Flow] = []
    for line in text.splitlines():
        match = FLOW_RE.search(line)
        if not match:
            continue
        risk_match = RISK_RE.search(line)
        risks = tuple(
            name.strip()
            for name in (RISK_NAME_RE.findall(risk_match.group(1)) if risk_match else [])
        )
        flows.append(Flow(match.group(1), match.group(2), match.group(3), risks))
    return flows


def parse_detected_protocols(text: str) -> list[str]:
    names: list[str] = []
    in_summary = False
    for line in text.splitlines():
        if line.startswith("Detected protocols:"):
            in_summary = True
            continue
        if not in_summary:
            continue
        if not line.strip():
            if names:
                break
            continue
        if line.startswith("Protocol statistics:"):
            break
        fields = line.split()
        if fields:
            names.append(fields[0])
    return names


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ManifestError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def load_manifest(path: Path) -> tuple[Path, list[dict[str, Any]]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(raw, dict) or raw.get("schema_version") != SCHEMA_VERSION:
        raise ManifestError("manifest schema_version must be 1")
    captures = raw.get("captures")
    if not isinstance(captures, list) or not captures:
        raise ManifestError("manifest must contain a non-empty captures array")

    root = path.resolve().parent
    validated: list[dict[str, Any]] = []
    ids: set[str] = set()
    sessions: set[str] = set()
    for index, entry in enumerate(captures):
        if not isinstance(entry, dict):
            raise ManifestError(f"captures[{index}] must be an object")
        capture_id = entry.get("id")
        session_id = entry.get("session_id")
        role = entry.get("role")
        expected = entry.get("expected")
        relative = entry.get("pcap")
        if not all(isinstance(value, str) and value.strip() for value in (capture_id, session_id, relative)):
            raise ManifestError(f"captures[{index}] requires non-empty id, session_id and pcap")
        if capture_id in ids:
            raise ManifestError(f"duplicate capture id: {capture_id}")
        if session_id in sessions:
            raise ManifestError(
                f"session {session_id!r} occurs more than once; captures are not session-disjoint"
            )
        if role not in ("target", "negative_control"):
            raise ManifestError(f"{capture_id}: role must be target or negative_control")
        if (
            not isinstance(expected, list) or not expected
            or any(not isinstance(token, str) or not token.strip() for token in expected)
        ):
            raise ManifestError(f"{capture_id}: expected must be a non-empty string array")
        capture_path = (root / relative).resolve()
        try:
            capture_path.relative_to(root)
        except ValueError as exc:
            raise ManifestError(f"{capture_id}: pcap path escapes the manifest directory") from exc
        if not capture_path.is_file():
            raise ManifestError(f"{capture_id}: capture does not exist: {relative}")
        ids.add(capture_id)
        sessions.add(session_id)
        validated.append({
            "id": capture_id,
            "session_id": session_id,
            "role": role,
            "expected": [token.strip() for token in expected],
            "path": capture_path,
        })
    return root, validated


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def run_tool(command: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise RuntimeError(f"cannot execute {Path(command[0]).name}: {exc}") from exc


def validate_udp_capture(tshark: str, path: Path, timeout: float) -> None:
    proc = run_tool([
        tshark, "-r", str(path), "-n", "-Y", "frame", "-T", "fields",
        "-E", "separator=\t", "-e", "frame.number", "-e", "udp.stream",
    ], timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"tshark exited with status {proc.returncode}")
    rows = [line.split("\t") for line in proc.stdout.splitlines() if line.strip()]
    if not rows:
        raise RuntimeError("capture has no frames")
    udp_rows = [row for row in rows if len(row) > 1 and row[1].strip()]
    if not udp_rows:
        raise RuntimeError("capture has no UDP flow")
    if len(udp_rows) != len(rows):
        raise RuntimeError("capture contains non-UDP frames; use an isolated UDP capture")


def classify_capture(ndpi: str, path: Path, timeout: float) -> tuple[list[Flow], list[str]]:
    proc = run_tool([ndpi, "-i", str(path), "-d", "-v", "2"], timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"ndpiReader exited with status {proc.returncode}")
    flows = parse_flows(proc.stdout)
    if not flows:
        raise RuntimeError("nDPI reported no flows")
    return flows, parse_detected_protocols(proc.stdout)


def evaluate_verdict(
    role: str, expected: list[str], flows: list[Flow], detected: list[str]
) -> tuple[bool, str]:
    brief = ", ".join(f"{flow.proto}/{flow.confidence}" for flow in flows)
    if role == "target":
        if any(is_vpn(flow) for flow in flows):
            return False, "flow is labelled as a known VPN or has a VPN/anonymisation risk"
        if not all(has_any_token(flow, expected) and flow.confidence == "DPI" for flow in flows):
            return False, f"not every flow matches {expected} with DPI confidence ({brief})"
        extra = [
            name for name in detected
            if not any(token_present(name, token) for token in expected)
        ]
        if extra:
            return False, f"nDPI summary contains unexpected protocols: {', '.join(extra)}"
        return True, f"whole capture matches {expected} with DPI confidence"

    # A negative control is valid only when it is Unknown or a known VPN.
    # Recognising some other benign protocol does not prove a useful control.
    if any(has_any_token(flow, expected) for flow in flows):
        return False, f"negative control still matches a target protocol ({brief})"
    if any(any(token_present(name, token) for token in expected) for name in detected):
        return False, "negative control summary still contains a target protocol"
    if not all(is_unknown(flow) or is_vpn(flow) for flow in flows):
        return False, f"negative control became another recognised benign protocol ({brief})"
    return True, f"negative control is Unknown/known-VPN ({brief})"


def evaluate_manifest(
    manifest_path: Path, ndpi: str, tshark: str, timeout: float = 60.0
) -> dict[str, Any]:
    _root, captures = load_manifest(manifest_path)
    hashes: set[str] = set()
    results: list[dict[str, Any]] = []
    for capture in captures:
        capture_hash = sha256_file(capture["path"])
        if capture_hash in hashes:
            raise ManifestError(
                f"{capture['id']}: duplicate capture bytes; captures are not independent"
            )
        hashes.add(capture_hash)
        result: dict[str, Any] = {
            "id": capture["id"],
            "session_id": capture["session_id"],
            "role": capture["role"],
            "expected": capture["expected"],
            "sha256": capture_hash,
            "passed": False,
        }
        try:
            validate_udp_capture(tshark, capture["path"], timeout)
            flows, detected = classify_capture(ndpi, capture["path"], timeout)
            passed, reason = evaluate_verdict(
                capture["role"], capture["expected"], flows, detected
            )
            result.update({
                "passed": passed,
                "reason": reason,
                "flows": [flow.public() for flow in flows],
                "detected_protocols": detected,
            })
        except RuntimeError as exc:
            result["reason"] = str(exc)
        results.append(result)
    passed = sum(1 for result in results if result["passed"])
    return {
        "schema_version": SCHEMA_VERSION,
        "passed": passed == len(results),
        "total": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "captures": results,
        "limitations": [
            "nDPI agreement is not proof of indistinguishability from real applications",
            "the gate does not test provider-specific DPI, active probing, or traffic correlation",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--ndpi", default="ndpiReader", help="path to ndpiReader")
    parser.add_argument("--tshark", default="tshark", help="path to tshark")
    parser.add_argument("--timeout", type=float, default=60.0, help="timeout per tool invocation")
    parser.add_argument("--output", type=Path, help="also write the JSON report here")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        report = evaluate_manifest(args.manifest, args.ndpi, args.tshark, args.timeout)
    except (ManifestError, OSError) as exc:
        print(f"udp-dpi-gate: {exc}", file=sys.stderr)
        return 2
    rendered = json.dumps(report, ensure_ascii=False, indent=2) + "\n"
    sys.stdout.write(rendered)
    if args.output:
        args.output.write_text(rendered, encoding="utf-8")
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
