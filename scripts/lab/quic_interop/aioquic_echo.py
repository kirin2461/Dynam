#!/usr/bin/env python3
"""aioquic echo peer for G4 real-QUIC interop testing (aioquic 1.3.0).

Protocol: one message per bidirectional stream; payload + FIN; echo returns
payload + FIN on the same stream. ALPN configurable (default "ncp-echo").

The installed service_identity 26.1.0 is incompatible with cryptography
44.0.2 on this host (broken `cryptography.hazmat.asn1` import). aioquic only
uses service_identity for hostname checks, so we install a minimal in-process
shim that implements hostname verification directly on the cryptography
module. No site-packages files are modified.

Server: aioquic_echo.py server --port P --cert C --key K [--alpn A]
        [--datagram]
Client: aioquic_echo.py client --host H --port P [--alpn A]
        (--insecure | --ca FILE [--sni NAME]) [--size N] [--count N]
        [--datagram [--dgram-count N] [--dgram-size N]]

With --datagram, RFC 9221 QUIC DATAGRAM support is advertised
(max_datagram_frame_size=65536). The server echoes every received datagram
back on the same connection. The client verifies that the peer negotiated
datagram support, sends --dgram-count datagrams of deterministic content,
and byte-compares each echo (datagrams are interleaved with any stream
messages on the same connection).

Client prints CONNECTED / ECHO_OK / DGRAM_OK / INTEROP_OK, exits 0 on
success. On the client, INTEROP_FAIL with exit 7 means the peer did not
advertise a max_datagram_frame_size transport parameter.
"""

import argparse
import asyncio
import ssl
import sys
import types


def _install_service_identity_shim():
    try:
        import service_identity  # noqa: F401
        return
    except Exception:
        pass
    import ssl as _ssl
    from cryptography import x509

    stub = types.ModuleType("service_identity")
    crypto_stub = types.ModuleType("service_identity.cryptography")

    class CertificateError(Exception):
        pass

    class VerificationError(CertificateError):
        pass

    def _dns_names(certificate):
        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            names = list(san.get_values_for_type(x509.DNSName))
            if names:
                return names
        except x509.ExtensionNotFound:
            pass
        return [a.value for a in certificate.subject.get_attributes_for_oid(
            x509.NameOID.COMMON_NAME)]

    def verify_certificate_hostname(certificate, hostname):
        for pattern in _dns_names(certificate):
            if _ssl._dnsname_match(pattern, hostname):
                return
        raise VerificationError(
            "hostname %r does not match certificate" % hostname)

    def verify_certificate_ip_address(certificate, ip_address):
        try:
            san = certificate.extensions.get_extension_for_class(
                x509.SubjectAlternativeName).value
            ips = san.get_values_for_type(x509.IPAddress)
        except x509.ExtensionNotFound:
            ips = []
        import ipaddress
        target = ipaddress.ip_address(ip_address)
        if any(target == ip for ip in ips):
            return
        raise VerificationError(
            "IP %r does not match certificate" % ip_address)

    def extract_patterns(certificate):
        return _dns_names(certificate)

    crypto_stub.verify_certificate_hostname = verify_certificate_hostname
    crypto_stub.verify_certificate_ip_address = verify_certificate_ip_address
    crypto_stub.extract_patterns = extract_patterns
    stub.cryptography = crypto_stub
    stub.CertificateError = CertificateError
    stub.VerificationError = VerificationError
    sys.modules["service_identity"] = stub
    sys.modules["service_identity.cryptography"] = crypto_stub


_install_service_identity_shim()

from aioquic.asyncio import connect, serve  # noqa: E402
from aioquic.asyncio.protocol import QuicConnectionProtocol  # noqa: E402
from aioquic.quic.configuration import QuicConfiguration  # noqa: E402
from aioquic.quic.events import (  # noqa: E402
    DatagramFrameReceived,
    StreamDataReceived,
)


def make_payload(n, seed):
    return bytes(((seed + (i * 131) % 251) & 0xFF) for i in range(n))


class EchoServer(QuicConnectionProtocol):
    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self._quic.send_stream_data(
                event.stream_id, event.data, end_stream=event.end_stream)
            self.transmit()
            sys.stdout.write("ECHOED stream=%d bytes=%d end=%d\n" % (
                event.stream_id, len(event.data), event.end_stream))
            sys.stdout.flush()
        elif isinstance(event, DatagramFrameReceived):
            self._quic.send_datagram_frame(event.data)
            self.transmit()
            sys.stdout.write("ECHOED_DGRAM bytes=%d\n" % len(event.data))
            sys.stdout.flush()


class EchoClient(QuicConnectionProtocol):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._queues = {}
        self._dgrams = asyncio.Queue()

    def quic_event_received(self, event):
        if isinstance(event, StreamDataReceived):
            self._queues.setdefault(event.stream_id, asyncio.Queue()).put_nowait(event)
        elif isinstance(event, DatagramFrameReceived):
            self._dgrams.put_nowait(event.data)

    async def roundtrip(self, payload):
        stream_id = self._quic.get_next_available_stream_id()
        q = self._queues.setdefault(stream_id, asyncio.Queue())
        self._quic.send_stream_data(stream_id, payload, end_stream=True)
        self.transmit()
        chunks = []
        while True:
            event = await asyncio.wait_for(q.get(), timeout=15)
            chunks.append(event.data)
            if event.end_stream:
                return stream_id, b"".join(chunks)

    async def dgram_roundtrip(self, payload):
        self._quic.send_datagram_frame(payload)
        self.transmit()
        return await asyncio.wait_for(self._dgrams.get(), timeout=15)


async def run_server(args):
    conf = QuicConfiguration(is_client=False, alpn_protocols=[args.alpn])
    if args.datagram:
        conf.max_datagram_frame_size = 65536
    conf.load_cert_chain(args.cert, args.key)
    server = await serve(args.bind, args.port, configuration=conf,
                         create_protocol=EchoServer)
    bound_port = args.port
    try:
        bound_port = server._transport.get_extra_info("sockname")[1]
    except Exception:
        pass
    print("LISTENING %s:%d" % (args.bind, bound_port), flush=True)
    await asyncio.Future()  # run until killed


async def run_client(args):
    conf = QuicConfiguration(is_client=True, alpn_protocols=[args.alpn])
    if args.datagram:
        conf.max_datagram_frame_size = 65536
    if args.insecure:
        conf.verify_mode = ssl.CERT_NONE
    elif args.ca:
        conf.load_verify_locations(args.ca)
    # aioquic 1.3.0: connect() takes SNI from the host argument.
    # For verified mode use a DNS host (e.g. localhost) matching the cert.
    async with connect(args.host, args.port, configuration=conf,
                       create_protocol=EchoClient) as proto:
        print("CONNECTED", flush=True)
        for i in range(args.count):
            payload = make_payload(args.size + i * 977, (i * 17) & 0xFF)
            sid, echo = await proto.roundtrip(payload)
            if echo != payload:
                print("INTEROP_FAIL echo mismatch msg=%d (%d != %d bytes)"
                      % (i, len(echo), len(payload)), file=sys.stderr)
                sys.exit(6)
            print("ECHO_OK stream=%d bytes=%d" % (sid, len(echo)), flush=True)
        dgrams_ok = 0
        if args.datagram:
            # Verify the peer actually negotiated RFC 9221 datagram support
            # (advertised max_datagram_frame_size transport parameter).
            remote_max = proto._quic._remote_max_datagram_frame_size
            if remote_max is None:
                print("INTEROP_FAIL peer did not negotiate QUIC DATAGRAM",
                      file=sys.stderr)
                sys.exit(7)
            print("DGRAM_NEGOTIATED peer_max_datagram_frame_size=%d"
                  % remote_max, flush=True)
            for i in range(args.dgram_count):
                n = min(args.dgram_size + i * 113, remote_max)
                payload = make_payload(n, (0x5A + i * 7) & 0xFF)
                echo = await proto.dgram_roundtrip(payload)
                if echo != payload:
                    print("INTEROP_FAIL datagram echo mismatch msg=%d "
                          "(%d != %d bytes)" % (i, len(echo), len(payload)),
                          file=sys.stderr)
                    sys.exit(8)
                dgrams_ok += 1
                print("DGRAM_OK bytes=%d" % len(echo), flush=True)
    print("INTEROP_OK messages=%d dgrams=%d" % (args.count, dgrams_ok))


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("mode", choices=["server", "client"])
    ap.add_argument("--bind", default="127.0.0.1")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, required=True)
    ap.add_argument("--cert")
    ap.add_argument("--key")
    ap.add_argument("--alpn", default="ncp-echo")
    ap.add_argument("--ca")
    ap.add_argument("--sni")
    ap.add_argument("--insecure", action="store_true")
    ap.add_argument("--size", type=int, default=512)
    ap.add_argument("--count", type=int, default=4)
    ap.add_argument("--datagram", action="store_true")
    ap.add_argument("--dgram-count", type=int, default=4)
    ap.add_argument("--dgram-size", type=int, default=600)
    args = ap.parse_args()
    if args.mode == "server":
        asyncio.run(run_server(args))
    else:
        asyncio.run(run_client(args))


if __name__ == "__main__":
    main()
