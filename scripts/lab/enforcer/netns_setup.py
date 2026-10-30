#!/usr/bin/env python3
"""Minimal pure-Python rtnetlink/ioctl network-namespace setup helper.

This host has no iproute2, so the AF_PACKET enforcer runner uses this helper
to create veth pairs, move peers into nested namespaces, assign addresses,
and bring links up. It only ever touches interfaces inside the disposable
namespaces created by run_controls_netns_afpacket.sh.
"""
import argparse
import ctypes
import os
import socket
import struct
import sys

NLMSG_ERROR = 2
RTM_NEWLINK = 16
NLM_F_REQUEST = 1
NLM_F_ACK = 4
NLM_F_CREATE = 0x400
NLM_F_EXCL = 0x200
IFLA_IFNAME = 3
IFLA_NET_NS_FD = 28
IFLA_LINKINFO = 18
IFLA_INFO_KIND = 1
IFLA_INFO_DATA = 2
VETH_INFO_PEER = 1
IFF_UP = 0x1
SIOCSIFADDR = 0x8916
SIOCSIFNETMASK = 0x891C
SIOCSIFFLAGS = 0x8914
SIOCGIFFLAGS = 0x8913
SIOCETHTOOL = 0x8946
ETHTOOL_STSO = 0x0000001F
ETHTOOL_SGSO = 0x00000024
ETHTOOL_SGRO = 0x0000002C
ETHTOOL_GSTRINGS = 0x0000001B
ETHTOOL_GSSET_INFO = 0x00000037
ETHTOOL_GFEATURES = 0x0000003A
ETHTOOL_SFEATURES = 0x0000003B
ETH_SS_FEATURES = 4
ETH_GSTRING_LEN = 32
CLONE_NEWNET = 0x40000000


def _nla(atype, data):
    length = 4 + len(data)
    pad = (4 - length % 4) % 4
    return struct.pack("HH", length, atype) + data + b"\x00" * pad


def _ifinfomsg(index=0, flags=0, change=0):
    return struct.pack("BxhiII", socket.AF_UNSPEC, 0, index, flags, change)


def _nlmsg(msg_type, flags, payload, seq):
    return struct.pack("IHHII", 16 + len(payload), msg_type, flags, seq, 0) + payload


def _rtnl_request(payload, create=True, seq=1):
    flags = NLM_F_REQUEST | NLM_F_ACK
    if create:
        flags |= NLM_F_CREATE | NLM_F_EXCL
    sock = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    try:
        sock.bind((0, 0))
        sock.send(_nlmsg(RTM_NEWLINK, flags, payload, seq))
        data = sock.recv(65535)
    finally:
        sock.close()
    msg_type = struct.unpack("H", data[2:4])[0]
    if msg_type == NLMSG_ERROR:
        err = struct.unpack("i", data[16:20])[0]
        if err:
            raise OSError(-err, os.strerror(-err))


def add_veth(name, peer_name, peer_pid):
    """Create veth pair NAME<->PEER_NAME in the current netns; move the peer
    into the network namespace of PEER_PID (IFLA_NET_NS_FD)."""
    ns_fd = os.open(f"/proc/{peer_pid}/ns/net", os.O_RDONLY)
    try:
        peer = _ifinfomsg() + _nla(IFLA_IFNAME, peer_name.encode() + b"\x00")
        peer += _nla(IFLA_NET_NS_FD, struct.pack("i", ns_fd))
        linkinfo = _nla(IFLA_INFO_KIND, b"veth\x00")
        linkinfo += _nla(IFLA_INFO_DATA, _nla(VETH_INFO_PEER, peer))
        payload = _ifinfomsg() + _nla(IFLA_IFNAME, name.encode() + b"\x00")
        payload += _nla(IFLA_LINKINFO, linkinfo)
        _rtnl_request(payload)
    finally:
        os.close(ns_fd)


def link_set(name, up=True):
    index = socket.if_nametoindex(name)
    flags = IFF_UP if up else 0
    payload = _ifinfomsg(index=index, flags=flags, change=IFF_UP)
    _rtnl_request(payload, create=False)


def setns(pid):
    ns_fd = os.open(f"/proc/{pid}/ns/net", os.O_RDONLY)
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        if libc.setns(ns_fd, CLONE_NEWNET) != 0:
            err = ctypes.get_errno()
            raise OSError(err, os.strerror(err))
    finally:
        os.close(ns_fd)


def _ifreq_addr(name, family, data4):
    ifr = name.encode()[:15].ljust(16, b"\x00")
    return ifr + struct.pack("H", family) + b"\x00\x00" + data4 + b"\x00" * 8


def addr_add(name, cidr):
    ip, prefix = cidr.split("/")
    prefix = int(prefix)
    mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF if prefix else 0
    addr = socket.inet_aton(ip)
    mask_b = struct.pack("!I", mask)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        import fcntl
        fcntl.ioctl(sock, SIOCSIFADDR, _ifreq_addr(name, socket.AF_INET, addr))
        fcntl.ioctl(sock, SIOCSIFNETMASK, _ifreq_addr(name, socket.AF_INET, mask_b))
    finally:
        sock.close()


def _ethtool_ioctl(name, value):
    import fcntl
    ifreq = name.encode()[:15].ljust(16, b"\x00")
    ifreq += struct.pack("P", ctypes.addressof(value))
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        fcntl.ioctl(sock, SIOCETHTOOL, ifreq, True)
    finally:
        sock.close()


def offload_set(name, feature, enabled):
    """Set TSO/GSO/GRO through SIOCETHTOOL (no external ethtool needed)."""
    commands = {"tso": ETHTOOL_STSO, "gso": ETHTOOL_SGSO,
                "gro": ETHTOOL_SGRO}
    if feature not in commands:
        raise ValueError(f"unsupported offload feature: {feature}")
    value = ctypes.create_string_buffer(struct.pack("II", commands[feature],
                                                   int(enabled)))
    _ethtool_ioctl(name, value)


def feature_set(name, feature, enabled):
    """Set a named ethtool feature and verify its active state.

    In particular, ``tx-udp-segmentation`` controls UDP_SEGMENT independent
    of the legacy generic GSO switch on some kernels/veth configurations.
    """
    info = ctypes.create_string_buffer(struct.pack(
        "IIQI", ETHTOOL_GSSET_INFO, 0, 1 << ETH_SS_FEATURES, 0))
    _ethtool_ioctl(name, info)
    count = struct.unpack_from("I", info.raw, 16)[0]
    if count == 0:
        raise OSError("interface exposes no ethtool feature names")
    strings = ctypes.create_string_buffer(12 + count * ETH_GSTRING_LEN)
    struct.pack_into("III", strings, 0, ETHTOOL_GSTRINGS,
                     ETH_SS_FEATURES, count)
    _ethtool_ioctl(name, strings)
    names = [strings.raw[12 + i * ETH_GSTRING_LEN:
                         12 + (i + 1) * ETH_GSTRING_LEN]
             .split(b"\x00", 1)[0].decode("ascii") for i in range(count)]
    try:
        index = names.index(feature)
    except ValueError as exc:
        raise OSError(f"interface has no ethtool feature {feature}") from exc
    blocks = (count + 31) // 32
    setting = ctypes.create_string_buffer(8 + blocks * 8)
    struct.pack_into("II", setting, 0, ETHTOOL_SFEATURES, blocks)
    bit = 1 << (index % 32)
    struct.pack_into("II", setting, 8 + (index // 32) * 8,
                     bit, bit if enabled else 0)
    _ethtool_ioctl(name, setting)

    current = ctypes.create_string_buffer(8 + blocks * 16)
    struct.pack_into("II", current, 0, ETHTOOL_GFEATURES, blocks)
    _ethtool_ioctl(name, current)
    active = struct.unpack_from("I", current, 8 + (index // 32) * 16 + 8)[0]
    if bool(active & bit) != bool(enabled):
        raise OSError(f"ethtool feature {feature} did not reach requested state")


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--netns-pid", type=int,
                        help="setns() into this pid's network namespace first")
    sub = parser.add_subparsers(dest="cmd", required=True)
    p = sub.add_parser("add-veth")
    p.add_argument("name")
    p.add_argument("peer_name")
    p.add_argument("--peer-pid", type=int, required=True)
    p = sub.add_parser("link-set")
    p.add_argument("name")
    p.add_argument("state", choices=("up", "down"))
    p = sub.add_parser("addr-add")
    p.add_argument("name")
    p.add_argument("cidr")
    p = sub.add_parser("offload-set")
    p.add_argument("name")
    p.add_argument("feature", choices=("tso", "gso", "gro"))
    p.add_argument("state", choices=("on", "off"))
    p = sub.add_parser("feature-set")
    p.add_argument("name")
    p.add_argument("feature")
    p.add_argument("state", choices=("on", "off"))
    args = parser.parse_args()
    if args.netns_pid:
        setns(args.netns_pid)
    if args.cmd == "add-veth":
        add_veth(args.name, args.peer_name, args.peer_pid)
    elif args.cmd == "link-set":
        link_set(args.name, up=args.state == "up")
    elif args.cmd == "addr-add":
        addr_add(args.name, args.cidr)
    elif args.cmd == "offload-set":
        offload_set(args.name, args.feature, args.state == "on")
    elif args.cmd == "feature-set":
        feature_set(args.name, args.feature, args.state == "on")
    return 0


if __name__ == "__main__":
    sys.exit(main())
