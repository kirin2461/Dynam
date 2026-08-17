#!/bin/bash
# Combined Server/DPI entrypoint — 2-NODE testbed variant.
# One container plays BOTH roles: the "real internet" server (HTTPS/443 +
# HTTP/80 with the DYNAM-TESTBED-OK marker) AND the DPI: iptables -m string
# on INPUT RST-injects any connection whose TLS ClientHello SNI / HTTP Host
# matches a blocked domain (per-packet, like a real inline DPI — so split
# desync genuinely evades it: no single segment carries the full hostname).
set -u

BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-forbidden.example,blocked.example}"
MARKER="DYNAM-TESTBED-OK"
WWW=/srv/www
mkdir -p "$WWW" /srv/certs

echo "<html><body>${MARKER}</body></html>" > "$WWW/index.html"
echo "ok" > "$WWW/healthz"

# --- TLS cert (SANs cover every served name; clients use -k anyway) ----------
NAMES="allowed.example,${BLOCKED_DOMAINS}"
IFS=',' read -ra arr <<< "$NAMES"
# -addext wants "DNS:a,DNS:b" (the DNS.1=/DNS.2= numbering is config-file
# syntax and makes openssl fail here).
SAN=""
for d in "${arr[@]}"; do SAN="${SAN},DNS:$d"; done
SAN="${SAN#,}"

if ! openssl req -x509 -newkey rsa:2048 -nodes -days 2 \
    -keyout /srv/certs/key.pem -out /srv/certs/cert.pem \
    -subj "/CN=dynam-testbed" -addext "subjectAltName=${SAN}"; then
    echo '[srv][FATAL] openssl cert generation failed'
    exit 1
fi
[ -s /srv/certs/cert.pem ] && [ -s /srv/certs/key.pem ] || { echo '[srv][FATAL] cert files missing'; exit 1; }
echo "[srv] cert SANs: $SAN"

# veth offloads reassemble split segments locally; desync packets must arrive
# at the server exactly as the client crafted them.
for iface in $(ls /sys/class/net | grep -v '^lo$'); do
    ethtool -K "$iface" tso off gso off gro off 2>/dev/null || true
done

# --- DPI: per-packet string match on INPUT (this container IS the DPI) -------
# No conntrack ESTABLISHED shortcut on purpose: the match must see the
# ClientHello / HTTP request packet of EVERY connection.
iptables -F INPUT
IFS=',' read -ra dparr <<< "$BLOCKED_DOMAINS"
for d in "${dparr[@]}"; do
    iptables -A INPUT -p tcp --dport 443 -m string --string "$d" --algo bm \
        -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp --dport 80 -m string --string "Host: $d" --algo bm \
        -j REJECT --reject-with tcp-reset
    echo "[dpi] blocking $d on INPUT (SNI + Host, RST injection)"
done
echo "[dpi] DPI active on-server. blocked: ${BLOCKED_DOMAINS}"

# --- servers ------------------------------------------------------------------
# Threaded HTTPS server with per-connection accept timeout and LAZY handshake:
# a connection stalled by desync (e.g. a sequence hole left by fake packets)
# must never wedge the accept loop. A naive wrap_socket() performs the
# per-connection TLS handshake INSIDE the accept loop — one damaged
# connection then blocks all future accepts, the backlog fills and every
# later connect times out (this bug cost us a full CI debugging round).
cat > /srv/https_server.py <<'PY'
import http.server, ssl, os, socket
os.chdir("/srv/www")

class TestbedHTTPS(http.server.ThreadingHTTPServer):
    daemon_threads = True
    def get_request(self):
        newsock, addr = self.socket.accept()
        newsock.settimeout(8)
        try:
            conn = self.ssl_context.wrap_socket(newsock, server_side=True,
                                                do_handshake_on_connect=False)
        except (ssl.SSLError, socket.error):
            newsock.close()
            raise
        return conn, addr

ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/srv/certs/cert.pem", "/srv/certs/key.pem")
httpd = TestbedHTTPS(("0.0.0.0", 443), http.server.SimpleHTTPRequestHandler)
httpd.ssl_context = ctx
httpd.serve_forever()
PY

python3 /srv/https_server.py &
cd "$WWW" && python3 -m http.server 80 &

echo "[srv] up on 80/443"
wait -n
