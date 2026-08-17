#!/bin/bash
# DPI-emulator entrypoint — combined Server/DPI container (2-node lab variant).
#
# Same TLS/HTTP server role as docker/dpi-server-2node.sh, but the DPI is the
# userspace emulator (dpi-emu.py, NFQUEUE + TCP reassembly) instead of kernel
# iptables -m string. INPUT tcp dport 443,80 is diverted into NFQUEUE 0.
# On SIGTERM: kill dpi-emu + servers and FLUSH the iptables rules so the
# container never dies leaving packets blackholed.
set -u

BLOCKED_DOMAINS="${BLOCKED_DOMAINS:-forbidden.example,blocked.example}"
DPI_MODEL="${DPI_MODEL:-reassemble}"
BUFFER_LIMIT="${BUFFER_LIMIT:-16384}"
OOO_POLICY="${OOO_POLICY:-permissive-first}"
NFQUEUE_NUM="${NFQUEUE_NUM:-0}"
MARKER="DYNAM-TESTBED-OK"
WWW=/srv/www
mkdir -p "$WWW" /srv/certs

echo "<html><body>${MARKER}</body></html>" > "$WWW/index.html"
echo "ok" > "$WWW/healthz"

# --- TLS cert (SANs cover every served name; clients use -k anyway) ----------
NAMES="allowed.example,${BLOCKED_DOMAINS}"
IFS=',' read -ra arr <<< "$NAMES"
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
# at the DPI exactly as the client crafted them.
for iface in $(ls /sys/class/net | grep -v '^lo$'); do
    ethtool -K "$iface" tso off gso off gro off 2>/dev/null || true
done

# --- DPI rules: model-dependent ----------------------------------------------
# off        = no DPI at all (allow-all; used by suite1 formation tests)
# string     = legacy per-packet iptables -m string match + tcp-reset
# reassemble = userspace NFQUEUE emulator with TCP reassembly (dpi-emu.py)
iptables -F INPUT
if [ "$DPI_MODEL" = "string" ]; then
    IFS=',' read -ra barr <<< "$BLOCKED_DOMAINS"
    for d in "${barr[@]}"; do
        iptables -A INPUT -p tcp --dport 443 -m string --string "$d" --algo bm \
            -j REJECT --reject-with tcp-reset
        iptables -A INPUT -p tcp --dport 80 -m string --string "Host: $d" --algo bm \
            -j REJECT --reject-with tcp-reset
    done
    echo "[dpi] INPUT string-match RST for: $BLOCKED_DOMAINS"
elif [ "$DPI_MODEL" = "reassemble" ]; then
    iptables -A INPUT -p tcp -m multiport --dports 443,80 \
        -j NFQUEUE --queue-num "$NFQUEUE_NUM"
    # FORWARD hook for a future 3-node midbox topology (harmless here: no
    # forwarding happens on the 2-node stand).
    iptables -A FORWARD -p tcp -m multiport --dports 443,80 \
        -j NFQUEUE --queue-num "$NFQUEUE_NUM" 2>/dev/null || true
    echo "[dpi] INPUT dport 443,80 -> NFQUEUE $NFQUEUE_NUM"
else
    echo "[dpi] DPI off (allow-all)"
fi

PIDS=""
cleanup() {
    echo "[entry] SIGTERM: stopping dpi-emu + servers, flushing iptables"
    # shellcheck disable=SC2086
    kill $PIDS 2>/dev/null || true
    iptables -F INPUT
    iptables -F FORWARD 2>/dev/null || true
    exit 0
}
trap cleanup TERM INT

# --- DPI emulator (reassemble model only) --------------------------------------
if [ "$DPI_MODEL" = "reassemble" ]; then
    python3 /dpi-emu.py --model "$DPI_MODEL" --buffer-limit "$BUFFER_LIMIT" \
        --ooo "$OOO_POLICY" --blocked "$BLOCKED_DOMAINS" --queue "$NFQUEUE_NUM" &
    PIDS="$PIDS $!"
    echo "[dpi] dpi-emu started (model=$DPI_MODEL buffer=$BUFFER_LIMIT ooo=$OOO_POLICY blocked=$BLOCKED_DOMAINS)"
fi

# --- servers (identical to dpi-server-2node.sh) -------------------------------
# Threaded HTTPS server with per-connection accept timeout and LAZY handshake:
# a connection stalled by desync must never wedge the accept loop.
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
PIDS="$PIDS $!"
cd "$WWW" && python3 -m http.server 80 &
PIDS="$PIDS $!"

echo "[srv] up on 80/443"
wait -n $PIDS
cleanup
