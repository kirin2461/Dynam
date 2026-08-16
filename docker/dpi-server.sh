#!/bin/bash
# DPI emulator entrypoint (runs inside the isolated container only).
# Sets up:
#   * HTTPS (443) + HTTP (80) servers answering with a DYNAM-TESTBED-OK marker
#   * iptables "DPI" rules that RST any connection carrying a blocked domain
#     (TLS ClientHello SNI on 443, Host header on 80)
#   * optional tc netem impairment (DPI_NETEM="delay 50ms loss 1%")
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
    echo '[dpi][FATAL] openssl cert generation failed'
    exit 1
fi
[ -s /srv/certs/cert.pem ] && [ -s /srv/certs/key.pem ] || { echo '[dpi][FATAL] cert files missing'; exit 1; }
echo "[dpi] cert SANs: $SAN"

# --- DPI rules (this container only; host is never touched) ------------------
# NB: no conntrack ESTABLISHED shortcut here on purpose — the string match
# must see the ClientHello / HTTP request packets of every connection.
iptables -F
for d in "${arr[@]}"; do
    [ "$d" = "allowed.example" ] && continue
    iptables -A INPUT -p tcp --dport 443 -m string --string "$d" --algo bm \
        -j REJECT --reject-with tcp-reset
    iptables -A INPUT -p tcp --dport 80 -m string --string "Host: $d" --algo bm \
        -j REJECT --reject-with tcp-reset
    echo "[dpi] blocking $d (SNI + Host, RST injection)"
done

# --- optional link impairment -------------------------------------------------
if [ -n "${DPI_NETEM:-}" ]; then
    tc qdisc add dev eth0 root netem $DPI_NETEM && echo "[dpi] netem: $DPI_NETEM"
fi

# --- servers ------------------------------------------------------------------
cat > /srv/https_server.py <<'PY'
import http.server, ssl, os
os.chdir("/srv/www")
httpd = http.server.ThreadingHTTPServer(("0.0.0.0", 443),
                                        http.server.SimpleHTTPRequestHandler)
ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ctx.load_cert_chain("/srv/certs/cert.pem", "/srv/certs/key.pem")
httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
httpd.serve_forever()
PY

python3 /srv/https_server.py &
cd "$WWW" && python3 -m http.server 80 &

echo "[dpi] up. blocked: ${BLOCKED_DOMAINS}"
wait -n
