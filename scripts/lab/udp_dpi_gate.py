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


SCHEMA_VERSION = 2
SUPPORTED_SCHEMA_VERSIONS = (1, 2)
CAPTURE_PHASES = {
    "handshake", "stable_data", "post_transition", "full_session", "probe",
}
# nDPI 5.x emits [Stack: ...]; the distro nDPI 4.2 flow format omits it.
# The stack is optional evidence only — never invent it during normalization.
FLOW_RE = re.compile(
    r"\[proto:\s*[0-9.]+/([^\]]+)\]"
    r"(?:\[Stack:\s*([^\]]+)\])?.*?"
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
        flows.append(Flow(match.group(1), match.group(2) or "", match.group(3), risks))
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


def load_manifest(path: Path) -> tuple[Path, int, list[dict[str, Any]]]:
    try:
        raw = json.loads(path.read_text(encoding="utf-8"), object_pairs_hook=reject_duplicate_keys)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ManifestError(f"cannot read manifest: {exc}") from exc
    if not isinstance(raw, dict):
        raise ManifestError("manifest must be a JSON object")
    schema_version = raw.get("schema_version")
    if schema_version not in SUPPORTED_SCHEMA_VERSIONS:
        raise ManifestError("manifest schema_version must be 1 or 2")
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
        roles = ("target", "negative_control", "positive_control") if schema_version == 2 else (
            "target", "negative_control"
        )
        if role not in roles:
            raise ManifestError(f"{capture_id}: unsupported role for schema {schema_version}")
        if (
            not isinstance(expected, list) or not expected
            or any(not isinstance(token, str) or not token.strip() for token in expected)
        ):
            raise ManifestError(f"{capture_id}: expected must be a non-empty string array")
        if schema_version == 2 and role in ("target", "positive_control") and len(expected) != 1:
            raise ManifestError(
                f"{capture_id}: schema-2 target/positive control requires exactly one "
                "expected protocol; use separate captures for separate protocols"
            )

        requirements = {
            "min_udp_packets": 1,
            "min_udp_bytes": 0,
            "min_duration_ms": 0,
            "require_bidirectional": False,
            "phase": "full_session",
        }
        if schema_version == 2:
            required = (
                "min_udp_packets", "min_udp_bytes", "min_duration_ms",
                "require_bidirectional", "phase",
            )
            if any(field not in entry for field in required):
                raise ManifestError(
                    f"{capture_id}: schema 2 requires {', '.join(required)}"
                )
            for field in ("min_udp_packets", "min_udp_bytes", "min_duration_ms"):
                value = entry[field]
                minimum = 1 if field == "min_udp_packets" else 0
                if isinstance(value, bool) or not isinstance(value, int) or value < minimum:
                    raise ManifestError(f"{capture_id}: {field} must be an integer >= {minimum}")
                requirements[field] = value
            if not isinstance(entry["require_bidirectional"], bool):
                raise ManifestError(f"{capture_id}: require_bidirectional must be boolean")
            requirements["require_bidirectional"] = entry["require_bidirectional"]
            if entry["phase"] not in CAPTURE_PHASES:
                raise ManifestError(
                    f"{capture_id}: phase must be one of {', '.join(sorted(CAPTURE_PHASES))}"
                )
            requirements["phase"] = entry["phase"]

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
            **requirements,
        })
    return root, schema_version, validated


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


def validate_udp_capture(
    tshark: str,
    path: Path,
    timeout: float,
    *,
    min_udp_packets: int = 1,
    min_udp_bytes: int = 0,
    min_duration_ms: int = 0,
    require_bidirectional: bool = False,
) -> list[dict[str, Any]]:
    """Validate every UDP stream without exposing addresses in the report.

    Schema-2 thresholds are per stream, not aggregate: several short flows must
    not combine to satisfy a long-flow requirement.
    """
    proc = run_tool([
        tshark, "-r", str(path), "-n", "-Y", "frame", "-T", "fields",
        "-E", "separator=\t", "-E", "occurrence=f",
        "-e", "frame.number", "-e", "udp.stream", "-e", "frame.time_epoch",
        "-e", "udp.length", "-e", "ip.src", "-e", "ipv6.src",
        "-e", "ip.dst", "-e", "ipv6.dst", "-e", "udp.srcport", "-e", "udp.dstport",
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

    streams: dict[str, dict[str, Any]] = {}
    try:
        for row in udp_rows:
            if len(row) < 10:
                raise ValueError("incomplete tshark fields")
            stream = row[1].strip()
            timestamp = float(row[2])
            udp_bytes = int(row[3])
            src = (row[4] or row[5], int(row[8]))
            dst = (row[6] or row[7], int(row[9]))
            if not src[0] or not dst[0]:
                raise ValueError("missing endpoint fields")
            stats = streams.setdefault(stream, {
                "packets": 0, "bytes": 0, "first": timestamp, "last": timestamp,
                "directions": set(),
            })
            stats["packets"] += 1
            stats["bytes"] += udp_bytes
            stats["first"] = min(stats["first"], timestamp)
            stats["last"] = max(stats["last"], timestamp)
            stats["directions"].add((src, dst))
    except (ValueError, IndexError) as exc:
        raise RuntimeError(f"invalid tshark UDP evidence: {exc}") from exc

    public: list[dict[str, Any]] = []
    for stream, stats in sorted(streams.items(), key=lambda item: int(item[0])):
        packets = stats["packets"]
        byte_count = stats["bytes"]
        duration_ms = int(round(max(0.0, stats["last"] - stats["first"]) * 1000))
        bidirectional = len(stats["directions"]) >= 2
        if packets < min_udp_packets:
            raise RuntimeError(
                f"UDP stream {stream} has {packets} packets; required {min_udp_packets}"
            )
        if byte_count < min_udp_bytes:
            raise RuntimeError(
                f"UDP stream {stream} has {byte_count} bytes; required {min_udp_bytes}"
            )
        if duration_ms < min_duration_ms:
            raise RuntimeError(
                f"UDP stream {stream} duration is {duration_ms} ms; required {min_duration_ms}"
            )
        if require_bidirectional and not bidirectional:
            raise RuntimeError(f"UDP stream {stream} is not bidirectional")
        public.append({
            "udp_stream": int(stream), "packets": packets, "udp_bytes": byte_count,
            "duration_ms": duration_ms, "bidirectional": bidirectional,
        })
    return public


def classify_capture(ndpi: str, path: Path, timeout: float) -> tuple[list[Flow], list[str]]:
    proc = run_tool([ndpi, "-i", str(path), "-d", "-v", "2"], timeout)
    if proc.returncode != 0:
        raise RuntimeError(f"ndpiReader exited with status {proc.returncode}")
    # nDPI 5.x writes the report to stdout; Debian nDPI 4.2 writes it to
    # stderr. Parse both channels without changing classifier output or rc.
    output = proc.stdout + ("\n" if proc.stdout and proc.stderr else "") + proc.stderr
    flows = parse_flows(output)
    if not flows:
        raise RuntimeError("nDPI reported no flows")
    return flows, parse_detected_protocols(output)


def evaluate_verdict(
    role: str, expected: list[str], flows: list[Flow], detected: list[str]
) -> tuple[bool, str]:
    brief = ", ".join(f"{flow.proto}/{flow.confidence}" for flow in flows)
    if role in ("target", "positive_control"):
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
    manifest_path: Path,
    ndpi: str,
    tshark: str,
    timeout: float = 60.0,
    ndpi_revision: str = "",
) -> dict[str, Any]:
    _root, schema_version, captures = load_manifest(manifest_path)
    hashes: set[str] = set()
    capture_hashes: dict[str, str] = {}
    for capture in captures:
        capture_hash = sha256_file(capture["path"])
        if capture_hash in hashes:
            raise ManifestError(
                f"{capture['id']}: duplicate capture bytes; captures are not independent"
            )
        hashes.add(capture_hash)
        capture_hashes[capture["id"]] = capture_hash

    toolchain: dict[str, Any] = {
        "ndpi_revision": ndpi_revision or None,
        "ndpi_version": None,
        "tshark_version": None,
    }
    toolchain_error = ""
    if schema_version == 2:
        try:
            for name, command in (
                ("ndpi_version", [ndpi, "--version"]),
                ("tshark_version", [tshark, "--version"]),
            ):
                proc = run_tool(command, timeout)
                version_output = proc.stdout if proc.stdout.strip() else proc.stderr
                # nDPI 4.2 prints valid version/help text but returns 1 for
                # --version. Accept only that documented informational case;
                # every other tool/version failure remains fail-closed.
                informational_ndpi_rc = (
                    name == "ndpi_version" and proc.returncode == 1
                    and bool(version_output.strip())
                )
                if proc.returncode != 0 and not informational_ndpi_rc:
                    raise RuntimeError(
                        f"{Path(command[0]).name} --version exited with status {proc.returncode}"
                    )
                version = next((line.strip() for line in version_output.splitlines() if line.strip()), "")
                if not version:
                    raise RuntimeError(f"{Path(command[0]).name} --version returned no version")
                toolchain[name] = version
        except RuntimeError as exc:
            toolchain_error = str(exc)

    results: list[dict[str, Any]] = []
    for capture in captures:
        result: dict[str, Any] = {
            "id": capture["id"],
            "session_id": capture["session_id"],
            "role": capture["role"],
            "phase": capture["phase"],
            "expected": capture["expected"],
            "sha256": capture_hashes[capture["id"]],
            "passed": False,
        }
        try:
            if toolchain_error:
                raise RuntimeError(toolchain_error)
            udp_evidence = validate_udp_capture(
                tshark, capture["path"], timeout,
                min_udp_packets=capture["min_udp_packets"],
                min_udp_bytes=capture["min_udp_bytes"],
                min_duration_ms=capture["min_duration_ms"],
                require_bidirectional=capture["require_bidirectional"],
            )
            flows, detected = classify_capture(ndpi, capture["path"], timeout)
            passed, reason = evaluate_verdict(
                capture["role"], capture["expected"], flows, detected
            )
            result.update({
                "passed": passed,
                "reason": reason,
                "udp_evidence": udp_evidence,
                "flows": [flow.public() for flow in flows],
                "detected_protocols": detected,
            })
        except RuntimeError as exc:
            result["reason"] = str(exc)
        results.append(result)

    # A schema-2 target is not self-validating: a passed, independent capture
    # of the real expected protocol must exist in the same disjoint run set.
    if schema_version == 2:
        for result in results:
            if result["role"] != "target" or not result["passed"]:
                continue
            expected = set(result["expected"])
            reference_ok = any(
                candidate["role"] == "positive_control" and candidate["passed"]
                and set(candidate["expected"]) == expected
                for candidate in results
            )
            if not reference_ok:
                result["passed"] = False
                result["reason"] = (
                    "target has no passed independent positive control with the same expected protocol"
                )

    passed = sum(1 for result in results if result["passed"])
    return {
        "schema_version": schema_version,
        "passed": passed == len(results),
        "total": len(results),
        "passed_count": passed,
        "failed_count": len(results) - passed,
        "toolchain": toolchain,
        "captures": results,
        "limitations": [
            "nDPI agreement is not proof of indistinguishability from real applications",
            "the gate does not test provider-specific DPI, active probing, or traffic correlation",
            "a positive control validates classifier/path sensitivity, not universal DPI bypass",
        ],
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--ndpi", default="ndpiReader", help="path to ndpiReader")
    parser.add_argument("--tshark", default="tshark", help="path to tshark")
    parser.add_argument("--timeout", type=float, default=60.0, help="timeout per tool invocation")
    parser.add_argument("--ndpi-revision", default="", help="pinned nDPI source revision for the evidence manifest")
    parser.add_argument("--output", type=Path, help="also write the JSON report here")
    args = parser.parse_args(argv)
    if args.timeout <= 0:
        parser.error("--timeout must be positive")
    try:
        report = evaluate_manifest(
            args.manifest, args.ndpi, args.tshark, args.timeout, args.ndpi_revision
        )
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
