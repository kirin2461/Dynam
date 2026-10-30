#!/usr/bin/env python3
# G5 TURN interop lab: minimal UDP echo peer (loopback only).
# Echoes every datagram back to its sender. Used as the "peer" behind the
# TURN relay: the client CreatePermission/ChannelBind targets this peer, and
# the peer's replies arrive via Data indications / ChannelData.
import socket
import sys


def main() -> int:
    if len(sys.argv) != 3:
        sys.stderr.write("usage: udp_echo_peer.py <bind_ip> <bind_port>\n")
        return 2
    ip, port = sys.argv[1], int(sys.argv[2])
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind((ip, port))
    print(f"udp_echo_peer listening on {ip}:{port}", flush=True)
    while True:
        data, addr = s.recvfrom(65535)
        s.sendto(data, addr)


if __name__ == "__main__":
    sys.exit(main())
