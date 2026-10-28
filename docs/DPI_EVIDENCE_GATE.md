# Independent UDP DPI evidence gate

`scripts/lab/udp_dpi_gate.py` adds an external-evidence check for UDP port
hopping, protocol morphing, and statistical mimicry. It complements the
existing TCP/TLS DPI Lab; it does not replace packet-level desync assertions.

The methodology is inspired by AIVPN's mask gate, but the implementation is
native to Dynam and does not change NCP packets, keys, sessions, or production
code.

## Why this gate exists

A unit test can prove that a `StatProfile` generates the distribution written
in its own configuration. It cannot prove that the resulting wire traffic is
classified like the target application. The gate therefore evaluates **whole
captures** with two tools that are independent of Dynam:

- **TShark** proves that the capture is non-empty and contains only UDP frames;
- **nDPI (`ndpiReader`)** classifies every flow and provides protocol confidence.

The gate rejects port-only matches, known-VPN labels, unexpected protocols in
the nDPI summary, repeated captures, and reused session identifiers.

## Capture requirements

1. Capture real Dynam wire traffic at the client/server boundary. Do not use
   the payload before Dynam's transport or mimicry layer.
2. Use one isolated UDP session per PCAP. Remove TCP canaries and unrelated
   traffic instead of mixing them into the capture.
3. Give every capture a unique `session_id`. Repeated runs of one session,
   slices of one PCAP, and derived corruptions are not independent evidence.
4. Include independently captured negative controls (random/corrupted traffic
   or a known VPN). A control is valid only when nDPI reports `Unknown` or a
   known VPN. If it becomes DNS, TLS, or another benign protocol, it is not a
   valid negative control for this experiment.
5. Keep private captures outside Git. The JSON report intentionally omits file
   paths, IP addresses, and payloads; it contains capture IDs, session labels,
   SHA-256 hashes, protocol labels, confidence, risks, and verdicts.

## Manifest

Paths are relative to the manifest and may not escape its directory.

```json
{
  "schema_version": 1,
  "captures": [
    {
      "id": "porthop-stun-run-01",
      "session_id": "fresh-session-01",
      "pcap": "captures/porthop-stun-run-01.pcap",
      "role": "target",
      "expected": ["STUN"]
    },
    {
      "id": "porthop-quic-run-02",
      "session_id": "fresh-session-02",
      "pcap": "captures/porthop-quic-run-02.pcap",
      "role": "target",
      "expected": ["QUIC"]
    },
    {
      "id": "random-control-run-03",
      "session_id": "fresh-session-03",
      "pcap": "captures/random-control-run-03.pcap",
      "role": "negative_control",
      "expected": ["STUN", "QUIC"]
    }
  ]
}
```

For a `target`, every flow must match at least one `expected` token with
`Confidence: DPI`, no flow may have a known-VPN label/risk, and the summary may
not contain unrelated protocols. For a `negative_control`, `expected` lists
the target protocols that must be absent.

## Run

Install TShark and nDPI, then run:

```bash
python3 scripts/lab/udp_dpi_gate.py /path/to/manifest.json \
  --ndpi /path/to/ndpiReader \
  --tshark /usr/bin/tshark \
  --output /path/to/report.json
```

Exit codes:

- `0`: every capture passed;
- `1`: at least one evidence check failed;
- `2`: invalid manifest, unsafe path, missing capture, or non-independent set.

Run the hermetic regressions without nDPI or TShark:

```bash
python3 scripts/lab/test_udp_dpi_gate.py
```

These tests run in the main CI workflow. A live nDPI result still requires real
PCAP input; the hermetic tests intentionally do not claim such a result.

## Interpretation and limits

Passing means only that the supplied captures received the requested nDPI
verdict. It does **not** prove statistical indistinguishability from genuine
WebRTC/Zoom/YouTube traffic, resistance to provider-specific DPI/TSPU, active
probing resistance, forward secrecy, or protection against traffic correlation.
Those properties need their own captures and adversarial tests.

For stronger statistical experiments, keep training, validation, and final
evaluation captures session-disjoint, freeze thresholds before the final run,
include genuine application captures, and publish sample sizes and negative
controls alongside the result.
