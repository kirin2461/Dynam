#!/usr/bin/env python3
"""Independent UDP/STUN controls for the disposable enforcer cell."""
import argparse
import json
import os
import socket
import struct
import sys
import time
from pathlib import Path

COOKIE = 0x2112A442
PORT = 45000
SERVER = "172.30.241.10"


def packet(kind, txid):
    if kind == "stun":
        return struct.pack("!HHI12s", 0x0001, 0, COOKIE, txid)
    if kind == "ph":
        return b"PH\x01" + bytes(17) + b"NCP-G1-LEGACY-CONTROL"
    if kind == "random":
        return os.urandom(96)
    raise ValueError(kind)


def expected_response(kind, request):
    if kind == "stun":
        return struct.pack("!HHI12s", 0x0101, 0, COOKIE, request[8:20])
    return request


def run_server(output):
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(("0.0.0.0", PORT))
    out = Path(output)
    with out.open("a", encoding="utf-8") as log:
        while True:
            data, peer = sock.recvfrom(65535)
            kind = "other"
            if len(data) >= 20 and data[:2] == b"\x00\x01" and data[4:8] == COOKIE.to_bytes(4, "big"):
                kind = "stun"
                response = expected_response(kind, data)
            else:
                response = data
            sock.sendto(response, peer)
            log.write(json.dumps({"kind": kind, "bytes": len(data)}) + "\n")
            log.flush()


def run_client(kind, expect, output):
    txid = bytes.fromhex("00112233445566778899aabb")
    request = packet(kind, txid)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(1.5)
    passed = False
    reason = "no response"
    started = time.monotonic()
    try:
        sock.sendto(request, (SERVER, PORT))
        response, _ = sock.recvfrom(65535)
        if response == expected_response(kind, request):
            passed = expect == "pass"
            reason = "valid response received"
        else:
            reason = "response integrity mismatch"
    except socket.timeout:
        passed = expect == "block"
        reason = "response timeout"
    finally:
        sock.close()
    result = {
        "schema_version": 1, "kind": kind, "expected": expect,
        "passed": passed, "reason": reason,
        "elapsed_ms": round((time.monotonic() - started) * 1000, 3),
    }
    Path(output).write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(result))
    return 0 if passed else 1


def main():
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="mode", required=True)
    server = sub.add_parser("server")
    server.add_argument("--output", required=True)
    client = sub.add_parser("client")
    client.add_argument("kind", choices=("stun", "ph", "random"))
    client.add_argument("expect", choices=("pass", "block"))
    client.add_argument("--output", required=True)
    args = parser.parse_args()
    if args.mode == "server":
        run_server(args.output)
        return 0
    return run_client(args.kind, args.expect, args.output)


if __name__ == "__main__":
    sys.exit(main())
