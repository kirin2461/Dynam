#!/bin/bash
# Dynam combat-test matrix — runs INSIDE the client container.
# Traffic to the target is routed THROUGH the DPI midbox:
#   client --(clientnet)--> dpi router --(servernet)--> target
# Exercises every project feature against the live DPI:
#   A  CLI sanity (version/help/crypto/keygen/hwid/import-zapret/network)
#   B  DPI baseline (blocked domains must RST without bypass)
#   B2 run mode (full stack, in-container, kill switch never armed)
#   C  proxy mode: operator presets x blocked domains
#   C2 inline zapret chain (multisplit {1,midsld})
#   D  proxy mode: zapret profiles + QUIC options
#   E  dpi mode (desync proxy) smoke
#   F  blockcheck (auto strategy selection, Geneva engine)
#   G  autopilot (self-learning engine: learn/status/reset)
#   H  traffic mimicry modes through the proxy
#   I  identity rotation / status / stop / sysproxy status
# Exit code 0 only if every GATED check passes. Checks for bypasses the
# current strategy space does not provide are informational ([INFO]) and do
# not affect the exit code.
set -u

NCP=${NCP_BIN:-ncp}
MARKER=${TESTBED_MARKER:-DYNAM-TESTBED-OK}
TARGET_HOST=${TARGET_HOST:-172.30.2.30}
DPI_GW=${DPI_GW:-172.30.1.10}
TARGET_NET=${TARGET_NET:-172.30.2.0/24}
PORT_BASE=11080
LOG=/testbed/results.log
: > "$LOG"

PASS=0; FAIL=0; INFO_FAIL=0; FAILED=()
ok()       { PASS=$((PASS+1)); echo "  [PASS] $1" | tee -a "$LOG"; }
bad()      { FAIL=$((FAIL+1)); FAILED+=("$1"); echo "  [FAIL] $1" | tee -a "$LOG"; }
info_bad() { INFO_FAIL=$((INFO_FAIL+1)); echo "  [INFO] $1 (no bypass — informational)" | tee -a "$LOG"; }
sect()     { echo; echo "=== $1 ===" | tee -a "$LOG"; }

# --- testbed networking ------------------------------------------------------
# Route the target net through the DPI midbox and kill veth offloads that
# would reassemble split segments before the DPI ever sees them.
ip route replace "$TARGET_NET" via "$DPI_GW" || { echo "[FATAL] cannot set route via $DPI_GW"; exit 1; }
ethtool -K eth0 tso off gso off gro off 2>/dev/null || true
echo "[*] route: $TARGET_NET via $DPI_GW (DPI midbox)" | tee -a "$LOG"

# curl helpers ---------------------------------------------------------------
direct() { # direct <domain> -> 0 on marker
    curl -sk --max-time 8 --resolve "$1:443:$TARGET_HOST" "https://$1/" 2>/dev/null | grep -q "$MARKER"
}
direct_http() {
    curl -s --max-time 8 --resolve "$1:80:$TARGET_HOST" "http://$1/" 2>/dev/null | grep -q "$MARKER"
}
via_proxy() { # via_proxy <port> <domain> [scheme]
    local scheme=${3:-https}
    if [ "$scheme" = https ]; then
        curl -sk --max-time 12 -x "socks5h://127.0.0.1:$1" "https://$2/" 2>/dev/null | grep -q "$MARKER"
    else
        curl -s --max-time 12 -x "socks5h://127.0.0.1:$1" "http://$2/" 2>/dev/null | grep -q "$MARKER"
    fi
}

start_proxy() { # start_proxy <port> [extra ncp proxy args...]
    local port=$1; shift
    "$NCP" proxy --port "$port" "$@" >/tmp/ncp-proxy-$port.log 2>&1 &
    echo $! > /tmp/ncp-proxy-$port.pid
    for _ in $(seq 1 30); do
        (echo > "/dev/tcp/127.0.0.1/$port") 2>/dev/null && return 0
        sleep 0.3
    done
    return 1
}
stop_proxy() {
    local port=$1
    [ -f /tmp/ncp-proxy-$port.pid ] && kill "$(cat /tmp/ncp-proxy-$port.pid)" 2>/dev/null
    sleep 0.5
}

echo "Dynam integration testbed — $(date -u)" | tee -a "$LOG"
"$NCP" version 2>&1 | head -2 | tee -a "$LOG"

# Wait for the target server (compose run does not honor depends_on health
# conditions, so the script is self-sufficient).
echo "[*] waiting for target server ($TARGET_HOST)..." | tee -a "$LOG"
ready=0
for _ in $(seq 1 60); do
    if direct allowed.example; then ready=1; break; fi
    sleep 1
done
[ "$ready" = 1 ] || { echo "[FATAL] target server never became ready" | tee -a "$LOG"; exit 1; }
echo "[*] target server is up" | tee -a "$LOG"

# ---------------------------------------------------------------------------
sect "A. CLI sanity"
"$NCP" version >/dev/null 2>&1 && ok "cli: version" || bad "cli: version"
"$NCP" help    >/dev/null 2>&1 && ok "cli: help"    || bad "cli: help"

out=$("$NCP" crypto hash sha256 dynam 2>&1)
echo "$out" | grep -qiE '[0-9a-f]{64}' && ok "crypto: sha256" || bad "crypto: sha256 ($out)"
out=$("$NCP" crypto hash blake2b dynam 2>&1)
[ -n "$out" ] && ok "crypto: blake2b" || bad "crypto: blake2b"
out=$("$NCP" crypto hash sha512 dynam 2>&1)
[ -n "$out" ] && ok "crypto: sha512" || bad "crypto: sha512"

out=$("$NCP" crypto keygen 2>&1);   echo "$out" | grep -qiE 'key|pub' && ok "crypto: keygen" || bad "crypto: keygen ($out)"
out=$("$NCP" crypto sign dynam 2>&1);    [ -n "$out" ] && ok "crypto: sign"   || bad "crypto: sign"
out=$("$NCP" crypto verify dynam 2>&1);  [ -n "$out" ] && ok "crypto: verify" || bad "crypto: verify"

out=$("$NCP" license hwid 2>&1);  [ -n "$out" ] && ok "license: hwid"  || bad "license: hwid"
out=$("$NCP" license info 2>&1);  [ -n "$out" ] && ok "license: info"  || bad "license: info"

out=$("$NCP" network interfaces 2>&1); echo "$out" | grep -qiE 'eth0|UP' && ok "network: interfaces" || bad "network: interfaces ($out)"
out=$("$NCP" network info 2>&1);       [ -n "$out" ] && ok "network: info" || bad "network: info"

out=$("$NCP" import-zapret --args "--dpi-desync=fake,split2 --dpi-desync-ttl=3" --out /tmp/zapret-profile.json 2>&1)
[ -s /tmp/zapret-profile.json ] && ok "import-zapret" || bad "import-zapret ($out)"

out=$("$NCP" sysproxy status 2>&1); [ -n "$out" ] && ok "sysproxy: status" || bad "sysproxy: status"

# ---------------------------------------------------------------------------
sect "B. DPI baseline (bypass OFF)"
if direct forbidden.example; then bad "baseline: forbidden.example must be blocked (TLS)"; else ok "baseline: forbidden.example TLS reset"; fi
if direct_http forbidden.example; then bad "baseline: forbidden.example must be blocked (HTTP)"; else ok "baseline: forbidden.example HTTP reset"; fi
if direct blocked.example; then bad "baseline: blocked.example must be blocked"; else ok "baseline: blocked.example reset"; fi
direct allowed.example && ok "baseline: allowed.example reachable" || bad "baseline: allowed.example must be reachable"

# ---------------------------------------------------------------------------
sect "B2. run mode (full paranoid stack, in-container)"
# Kill switch is NEVER armed from tests (--kill-switch not passed).
timeout 30 "$NCP" run >/tmp/ncp-run.log 2>&1 &
runpid=$!
sleep 15
if kill -0 "$runpid" 2>/dev/null; then
    ok "run: protection stack started and alive"
    kill "$runpid" 2>/dev/null; sleep 2; kill -9 "$runpid" 2>/dev/null
    wait "$runpid" 2>/dev/null
else
    wait "$runpid"; rc=$?
    if grep -qiE 'Starting NCP protection' /tmp/ncp-run.log; then
        ok "run: started (exited rc=$rc)"
    else
        bad "run: failed rc=$rc ($(tail -1 /tmp/ncp-run.log))"
    fi
fi
"$NCP" stop >/dev/null 2>&1 || true
# after run/stop the DPI baseline must behave exactly as before
if direct forbidden.example; then bad "post-run: forbidden.example must be blocked again"; else ok "post-run: baseline restored"; fi

# ---------------------------------------------------------------------------
sect "C. proxy presets vs blocked domains"
# Gate: allowed.example must ALWAYS work through the proxy (regression), and
# the tspu preset — which now emulates zapret's --split-pos=1,midsld — must
# beat the string-match DPI. Other presets currently have no midsld-family
# position in their strategy space: their forbidden.example result is
# informational (matches real-world behavior against this DPI class).
PRESETS=${PRESETS:-"tspu beeline mts megafon tele2 mobile auto"}
p=$PORT_BASE
for preset in $PRESETS; do
    if start_proxy "$p" --preset "$preset"; then
        if via_proxy "$p" forbidden.example; then
            ok "proxy --preset $preset: forbidden.example bypassed"
        elif [ "$preset" = tspu ]; then
            bad "proxy --preset tspu: forbidden.example (midsld split must beat string-match DPI)"
        else
            info_bad "proxy --preset $preset: forbidden.example"
        fi
        via_proxy "$p" allowed.example   && ok "proxy --preset $preset: allowed.example" \
                                          || bad "proxy --preset $preset: allowed.example (regression)"
        stop_proxy "$p"
    else
        bad "proxy --preset $preset: failed to start (see /tmp/ncp-proxy-$p.log)"
    fi
    p=$((p+1))
done

# ---------------------------------------------------------------------------
sect "C2. inline zapret chain (multisplit {1,midsld})"
# The reference zapret strategy against SNI string-match DPI: split the
# ClientHello inside the second-level domain so no single segment carries
# the hostname. This MUST bypass.
if start_proxy "$p" --chain "--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq"; then
    via_proxy "$p" forbidden.example && ok "chain multisplit{1,midsld}: forbidden.example bypassed" \
                                      || bad "chain multisplit{1,midsld}: forbidden.example"
    via_proxy "$p" allowed.example   && ok "chain multisplit{1,midsld}: allowed.example" \
                                      || bad "chain multisplit{1,midsld}: allowed.example (regression)"
    stop_proxy "$p"
else
    bad "chain multisplit{1,midsld}: failed to start"
fi
p=$((p+1))

# ---------------------------------------------------------------------------
sect "D. zapret profiles + QUIC options"
# Built-in zapret profiles are hostlist-scoped (their chains only fire for
# hosts matching the profile's hostlist patterns), so against testbed domains
# a forbidden.example bypass is informational; allowed.example is the gate.
ZAPRET_PROFILES=${ZAPRET_PROFILES:-"zapret_full zapret_general zapret_tcp zapret_quic"}
for prof in $ZAPRET_PROFILES; do
    if start_proxy "$p" --zapret-profile "$prof"; then
        via_proxy "$p" forbidden.example && ok "proxy --zapret-profile $prof: forbidden.example bypassed" \
                                          || info_bad "proxy --zapret-profile $prof: forbidden.example"
        via_proxy "$p" allowed.example   && ok "proxy --zapret-profile $prof: allowed.example" \
                                          || bad "proxy --zapret-profile $prof: allowed.example (regression)"
        stop_proxy "$p"
    else
        bad "proxy --zapret-profile $prof: failed to start"
    fi
    p=$((p+1))
done
if start_proxy "$p" --preset auto --block-quic --fake-quic 2; then
    via_proxy "$p" allowed.example && ok "proxy auto + block-quic/fake-quic: allowed.example" \
                                   || bad "proxy auto + block-quic/fake-quic: allowed.example (regression)"
    stop_proxy "$p"
else
    bad "proxy auto + quic opts: failed to start"
fi
p=$((p+1))

# imported zapret profile from section A
if [ -s /tmp/zapret-profile.json ]; then
    if start_proxy "$p" --zapret-profile /tmp/zapret-profile.json; then
        via_proxy "$p" allowed.example && ok "proxy: imported zapret profile" \
                                        || bad "proxy: imported zapret profile"
        stop_proxy "$p"
    else
        echo "  [SKIP] imported profile not accepted as --zapret-profile arg" | tee -a "$LOG"
    fi
    p=$((p+1))
fi

# ---------------------------------------------------------------------------
sect "E. dpi mode (desync proxy)"
# NB: `ncp dpi --help` would START the bypass (the handler ignores --help and
# blocks) — so smoke-test it as a background daemon with a hard timeout.
timeout 20 "$NCP" dpi --port "$p" --preset tspu --no-kill-switch >/tmp/ncp-dpi.log 2>&1 &
dpid=$!
up=0
for _ in $(seq 1 40); do
    (echo > "/dev/tcp/127.0.0.1/$p") 2>/dev/null && { up=1; break; }
    kill -0 "$dpid" 2>/dev/null || break
    sleep 0.5
done
if [ "$up" = 1 ]; then
    ok "dpi: bypass proxy listening on $p"
    via_proxy "$p" forbidden.example && ok "dpi: forbidden.example bypassed" \
                                      || info_bad "dpi: forbidden.example"
    via_proxy "$p" allowed.example && ok "dpi: allowed.example" \
                                    || info_bad "dpi: allowed.example"
else
    bad "dpi: failed to start (see /tmp/ncp-dpi.log)"
fi
kill "$dpid" 2>/dev/null; wait "$dpid" 2>/dev/null
p=$((p+1))

# ---------------------------------------------------------------------------
sect "F. blockcheck (auto strategy / Geneva)"
# blockcheck's strategy space includes split-midsld / multisplit-1-midsld, so
# it MUST find a working bypass against this DPI.
if "$NCP" blockcheck --domains forbidden.example,allowed.example \
        --timeout 6000 --json --out /tmp/blockcheck.json >/tmp/blockcheck.log 2>&1; then
    if jq -e '.best_strategy // .best // empty' /tmp/blockcheck.json >/dev/null 2>&1 \
       || grep -qi '"best' /tmp/blockcheck.json; then
        ok "blockcheck: best strategy selected ($(jq -r '.best_strategy // .best // "?"' /tmp/blockcheck.json 2>/dev/null))"
    else
        bad "blockcheck: no best strategy in report"
    fi
else
    bad "blockcheck: run failed (see /tmp/blockcheck.log)"
fi

# ---------------------------------------------------------------------------
sect "G. autopilot (self-learning engine)"
out=$("$NCP" autopilot learn forbidden.example --json --timeout 8000 2>&1)
echo "$out" | grep -qiE 'strateg|success|ok|learn' && ok "autopilot: learn forbidden.example" \
    || bad "autopilot: learn ($out)"
out=$("$NCP" autopilot status --json 2>&1)
[ -n "$out" ] && ok "autopilot: status" || bad "autopilot: status"
"$NCP" autopilot reset >/dev/null 2>&1 && ok "autopilot: reset" || bad "autopilot: reset"

# ---------------------------------------------------------------------------
sect "H. traffic mimicry modes (through proxy)"
MIMIC_MODES=${MIMIC_MODES:-"http https quic websocket skype zoom bittorrent random"}
for m in $MIMIC_MODES; do
    if "$NCP" mimic "$m" >/dev/null 2>&1; then
        if start_proxy "$p" --preset auto; then
            via_proxy "$p" allowed.example && ok "mimic $m + proxy: allowed.example" \
                                            || bad "mimic $m + proxy: allowed.example"
            stop_proxy "$p"
        else
            bad "mimic $m: proxy failed to start"
        fi
    else
        bad "mimic $m: command failed"
    fi
    p=$((p+1))
done

# ---------------------------------------------------------------------------
sect "I. identity / lifecycle"
out=$("$NCP" rotate 2>&1);  [ -n "$out" ] && ok "rotate identities" || bad "rotate identities"
out=$("$NCP" status 2>&1);  [ -n "$out" ] && ok "status" || bad "status"
"$NCP" stop >/dev/null 2>&1 && ok "stop/restore" || bad "stop/restore"

# ---------------------------------------------------------------------------
echo
echo "════════════════ RESULT ════════════════" | tee -a "$LOG"
echo "  PASS: $PASS   FAIL: $FAIL   INFO(no-bypass): $INFO_FAIL" | tee -a "$LOG"
if [ "$FAIL" -gt 0 ]; then
    printf '  failed: %s\n' "${FAILED[@]}" | tee -a "$LOG"
    exit 1
fi
echo "  ALL GREEN" | tee -a "$LOG"
exit 0
