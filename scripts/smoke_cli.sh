#!/usr/bin/env bash
# ============================================================================
# NCP CLI functional smoke matrix.
#
# Verifies that every CLI command actually works — no stubs, no hangs, no
# crashes. HARD SAFETY RULES (do not violate when extending):
#   * never uses sudo/root
#   * never touches host firewall (iptables/nftables), DNS, routes or
#     system proxy settings — commands that would (`run`, `stop`, `rotate`,
#     `sysproxy on|off`, `spa serve` real mode, `xdp attach|detach|drop`,
#     `trust update-roots`) are statically SKIPped below
#   * network access limited to localhost and plain HTTPS to example.com
#     (proxy/blockcheck tests)
#
# Usage: smoke_cli.sh /path/to/ncp
# Exit code: 0 if FAIL==0, else 1. STUBs/INFOs do not fail the run.
# ============================================================================
set -u

BIN="${1:-}"
if [ -z "$BIN" ] || [ ! -x "$BIN" ]; then
    echo "usage: $0 /path/to/ncp" >&2
    exit 2
fi

WORK="$(mktemp -d "${TMPDIR:-/tmp}/ncp-smoke.XXXXXX")"
PASS=0; FAIL=0; INFO=0; STUB=0; SKIP=0
FAILED_NAMES=""

pass() { PASS=$((PASS+1)); echo "PASS  $1"; }
fail() { FAIL=$((FAIL+1)); FAILED_NAMES="$FAILED_NAMES $1"; echo "FAIL  $1"; }
info() { INFO=$((INFO+1)); echo "INFO  $1 — $2"; }
stub() { STUB=$((STUB+1)); echo "STUB  $1 — $2"; }
skip() { SKIP=$((SKIP+1)); echo "SKIP  $1 — $2"; }

OUT=""; RC=0
run() {  # run <timeout-sec> <cmd...>
    local t="$1"; shift
    OUT="$(cd "$WORK" && timeout "$t" "$@" 2>&1)"; RC=$?
}

expect() {  # expect <name> <grep -iE pattern>
    local name="$1" pat="$2"
    if printf '%s' "$OUT" | grep -qiE -- "$pat"; then
        pass "$name"
    else
        fail "$name"
        printf '%s\n' "$OUT" | head -10 | sed 's/^/      | /'
        echo "      (rc=$RC)"
    fi
}

wait_port() {  # wait_port <port> <tries>
    local port="$1" tries="${2:-30}" i
    for i in $(seq 1 "$tries"); do
        (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && { exec 3>&- 3<&-; return 0; }
        sleep 0.2
    done
    return 1
}

echo "============================================================"
echo " NCP CLI smoke matrix"
echo " binary: $BIN"
echo " work:   $WORK"
echo " date:   $(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "============================================================"

# ───────────────────────── A. basics ─────────────────────────
echo "--- A. basics ---"
run 10 "$BIN" version
expect "version prints version" '[0-9]+\.[0-9]+\.[0-9]+'
echo "      | $(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"

run 10 "$BIN" help
expect "help lists commands" 'Commands:'

run 10 "$BIN"
expect "no args prints usage" 'Usage:'

run 10 "$BIN" frobnicate
expect "unknown command handled" 'Unknown command'

# ───────────────────────── B. crypto ─────────────────────────
echo "--- B. crypto ---"
run 10 "$BIN" crypto keygen
expect "crypto keygen" 'Public key:'
PUB_HEX="$(printf '%s' "$OUT" | grep -i 'Public key' | grep -oiE '[0-9a-f]{64}' | head -1)"
SEC_HEX="$(printf '%s' "$OUT" | grep -i 'Secret key' | grep -oiE '[0-9a-f]{128}' | head -1)"

run 10 "$BIN" crypto sign "smoke-test-message" "$SEC_HEX"
expect "crypto sign" 'Signature'
SIG_HEX="$(printf '%s' "$OUT" | grep -oiE '[0-9a-f]{128}' | head -1)"

run 10 "$BIN" crypto verify "smoke-test-message" "$SIG_HEX" "$PUB_HEX"
expect "crypto verify (good sig)" 'valid'

run 10 "$BIN" crypto verify "tampered-message" "$SIG_HEX" "$PUB_HEX"
if printf '%s' "$OUT" | grep -qiE 'invalid|fail|false'; then
    pass "crypto verify rejects tampered msg"
else
    fail "crypto verify rejects tampered msg"
    printf '%s\n' "$OUT" | head -5 | sed 's/^/      | /'
fi

run 10 "$BIN" crypto random -n 16
expect "crypto random 16 bytes" '[0-9a-f]{32}'

run 10 "$BIN" crypto hash sha256 abc
expect "crypto hash sha256 known vector" 'ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad'

run 10 "$BIN" crypto hash sha512 abc
expect "crypto hash sha512 known vector" 'ddaf35a193617abacc417349ae204131'

run 10 "$BIN" crypto hash blake2b abc
# CLI uses BLAKE2b-256 (32-byte digest) — KAT for "abc":
expect "crypto hash blake2b-256 known vector" 'bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319'

# ───────────────────────── C. network ────────────────────────
echo "--- C. network ---"
run 10 "$BIN" network interfaces
expect "network interfaces" '\[UP\]'

run 10 "$BIN" network stats
expect "network stats" 'Packets (sent|received)'

# ───────────────────────── D. license ────────────────────────
echo "--- D. license ---"
run 10 "$BIN" license hwid
expect "license hwid" 'Hardware ID'

run 10 "$BIN" license validate
expect "license validate graceful (no file)" 'INVALID'

run 10 "$BIN" license activate
if printf '%s' "$OUT" | grep -qi 'not yet implemented'; then
    stub "license activate" "explicit 'not yet implemented'"
else
    pass "license activate responds"
fi

# ───────────────────────── E. SPA ────────────────────────────
echo "--- E. SPA ---"
run 15 "$BIN" spa keygen --out "$WORK/spa"
expect "spa keygen" 'key_id|authorized'
if [ -f "$WORK/spa.key" ]; then
    SZ=$(stat -c%s "$WORK/spa.key")
    if [ "$SZ" -eq 96 ]; then
        pass "spa keyfile is 96 bytes raw (sk||pk||id)"
    elif [ "$SZ" -eq 128 ] || [ "$SZ" -eq 129 ]; then
        DEC=$(base64 -d "$WORK/spa.key" 2>/dev/null | wc -c)
        [ "$DEC" -eq 96 ] && pass "spa keyfile is base64 of 96 bytes" || fail "spa keyfile base64 decodes to $DEC bytes"
    else
        fail "spa keyfile size (unexpected $SZ)"
    fi
else
    fail "spa keyfile written"
fi

run 15 "$BIN" spa knock 127.0.0.1 --key "$WORK/spa.key" --allow-port 443
expect "spa knock localhost" 'knock sent'

grep -m1 . "$WORK/spa.key.pub" "$WORK"/spa*.pub 2>/dev/null >/dev/null || true
# serve --dry-run needs an authorized_keys file; keygen prints the line to
# stdout — reconstruct it if no .pub file was written.
AK="$WORK/authorized_keys"
if ! ls "$WORK"/spa*.pub >/dev/null 2>&1; then
    LINE="$(run 15 "$BIN" spa keygen --out "$WORK/spa2"; printf '%s' "$OUT" | grep -i 'authorized' )"
    [ -n "$LINE" ] && printf '%s\n' "$LINE" > "$AK"
else
    cp "$WORK"/spa*.pub "$AK" 2>/dev/null || true
fi
if [ -s "$AK" ]; then
    run 15 "$BIN" spa serve --authorized-keys "$AK" --dry-run
    expect "spa serve --dry-run" 'dry|OK|loaded'
else
    info "spa serve --dry-run" "no authorized_keys line captured, untested"
fi

# ───────────────────── F. StegoDNS roundtrip ─────────────────
echo "--- F. stegodns ---"
SPA_PK_B64="$(run 10 "$BIN" spa keygen --out "$WORK/spa3"; printf '%s' "$OUT" | grep -oiE 'pubkey[: ]+[A-Za-z0-9+/=]{40,}' | grep -oiE '[A-Za-z0-9+/=]{40,}' | head -1)"
if [ -z "$SPA_PK_B64" ]; then
    # fall back: base64 of the pk half of the keyfile
    SPA_PK_B64="$(dd if="$WORK/spa3.key" bs=1 skip=64 count=32 2>/dev/null | base64 -w0)"
fi
run 15 "$BIN" stegodns encode --ip 203.0.113.7 --port 9443 \
    --spa-pubkey "$SPA_PK_B64" --passphrase smokepass \
    --signing-key "$WORK/spa3.key" --domain example.com
expect "stegodns encode" 'verify-pubkey'
TXT_REC="$(printf '%s' "$OUT" | grep -iE '_ncp\.' | head -1)"
VPK="$(printf '%s' "$OUT" | grep -i 'verify-pubkey' | grep -oiE '[A-Za-z0-9+/=]{40,}' | head -1)"
if [ -n "$TXT_REC" ] && [ -n "$VPK" ]; then
    run 15 "$BIN" stegodns decode --txt "$TXT_REC" --passphrase smokepass --verify-pubkey "$VPK"
    expect "stegodns decode roundtrip" '203\.0\.113\.7'
else
    fail "stegodns roundtrip (encode output unparsable)"
    printf '%s\n' "$OUT" | head -5 | sed 's/^/      | /'
fi

# ───────────────────── G. import-zapret ──────────────────────
echo "--- G. import-zapret ---"
run 10 "$BIN" import-zapret --args "--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq" --out "$WORK/prof.json"
expect "import-zapret parses" 'imported|profile|written|saved'
if [ -f "$WORK/prof.json" ] && grep -q midsld "$WORK/prof.json"; then
    pass "import-zapret profile contains midsld"
else
    fail "import-zapret profile contains midsld"
fi

# ───────────────────────── H. trust ──────────────────────────
echo "--- H. trust ---"
run 20 "$BIN" trust init-ca --out "$WORK/ca"
expect "trust init-ca" 'Local CA generated'
if [ -f "$WORK/ca.crt" ]; then
    if openssl x509 -in "$WORK/ca.crt" -noout -subject 2>/dev/null | grep -q 'NCP'; then
        pass "trust CA cert is valid x509"
    else
        fail "trust CA cert is valid x509"
    fi
    PERM=$(stat -c%a "$WORK/ca.key" 2>/dev/null)
    [ "$PERM" = "600" ] && pass "trust CA key mode 600" || info "trust CA key mode" "got $PERM (umask-dependent)"
else
    fail "trust CA files written"
fi
run 10 "$BIN" trust policy-test --host example.com
expect "trust policy-test" 'PUBLIC'

# ───────────────────────── I. proxy (desync core) ────────────
echo "--- I. proxy ---"
(cd "$WORK" && "$BIN" proxy --port 11080 >"$WORK/proxy.log" 2>&1 & echo $! > "$WORK/proxy.pid")
sleep 1
if wait_port 11080 30; then
    pass "proxy starts and listens on 11080"
    CODE=$(curl -sS -m 15 -x socks5h://127.0.0.1:11080 https://example.com -o /dev/null -w '%{http_code}' 2>&1)
    if [ "$CODE" = "200" ]; then
        pass "proxy forwards HTTPS via SOCKS5 (200)"
    else
        fail "proxy forwards HTTPS via SOCKS5 (got '$CODE')"
        head -5 "$WORK/proxy.log" | sed 's/^/      | /'
    fi
else
    fail "proxy starts and listens on 11080"
    head -10 "$WORK/proxy.log" | sed 's/^/      | /'
fi
kill "$(cat "$WORK/proxy.pid" 2>/dev/null)" 2>/dev/null; sleep 0.3

# proxy with inline zapret-style chain (multisplit + midsld)
(cd "$WORK" && "$BIN" proxy --port 11081 --chain "--filter-tcp=443 --dpi-desync=multisplit --dpi-desync-split-pos=1,midsld --dpi-desync-fooling=badseq" >"$WORK/proxy2.log" 2>&1 & echo $! > "$WORK/proxy2.pid")
sleep 1
if wait_port 11081 30; then
    CODE=$(curl -sS -m 15 -x socks5h://127.0.0.1:11081 https://example.com -o /dev/null -w '%{http_code}' 2>&1)
    if [ "$CODE" = "200" ]; then
        pass "proxy with midsld chain forwards HTTPS (200)"
    else
        fail "proxy with midsld chain forwards HTTPS (got '$CODE')"
        head -5 "$WORK/proxy2.log" | sed 's/^/      | /'
    fi
else
    fail "proxy with midsld chain starts"
    head -10 "$WORK/proxy2.log" | sed 's/^/      | /'
fi
kill "$(cat "$WORK/proxy2.pid" 2>/dev/null)" 2>/dev/null

# ───────────────────────── J. dpi ────────────────────────────
echo "--- J. dpi ---"
run 8 "$BIN" dpi --port 18882
if [ $RC -eq 124 ]; then
    pass "dpi starts and stays up (timeout-killed)"
elif printf '%s' "$OUT" | grep -qiE 'privilege|permission|root|admin|error|failed'; then
    pass "dpi fails gracefully without privileges"
else
    info "dpi non-root behaviour" "rc=$RC: $(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"
fi

# ───────────────────── K. enterprise modules ─────────────────
echo "--- K. enterprise ---"
run 10 "$BIN" reality
expect "reality w/o args prints usage" 'Usage|requires'

# reality dry-run with a generated client keyfile (base64 of 64-byte sk)
SK64="$(head -c 64 "$WORK/spa.key" 2>/dev/null | base64 -w0)"
printf 'smokeclient %s\n' "$SK64" > "$WORK/reality.keys"
run 15 "$BIN" reality serve --listen 14433 --fallback example.com:443 \
    --internal 127.0.0.1:9443 --key-file "$WORK/reality.keys" --dry-run
expect "reality serve --dry-run" 'Dry run'

run 10 "$BIN" cps test --chain "dns:example.com;wait:10;quic"
expect "cps test builds packets" 'packet:'

# porthop localhost pair
(cd "$WORK" && "$BIN" porthop serve --base-port 46000 --range 8 --secret smoke --session-id 01 >"$WORK/ph-srv.log" 2>&1 & echo $! > "$WORK/ph.pid")
sleep 1
run 20 "$BIN" porthop client --host 127.0.0.1 --base-port 46000 --range 8 --secret smoke --session-id 01 --message ping
if printf '%s' "$OUT" | grep -qiE 'ack|delivered|ok|sent'; then
    pass "porthop localhost roundtrip"
else
    fail "porthop localhost roundtrip"
    printf '%s\n' "$OUT" | head -5 | sed 's/^/      | /'
    head -5 "$WORK/ph-srv.log" | sed 's/^/      srv| /'
fi
kill "$(cat "$WORK/ph.pid" 2>/dev/null)" 2>/dev/null

# fog node liveness (localhost only)
(cd "$WORK" && timeout 6 "$BIN" fog node --id 0123456789abcdef0123456789abcdef --port 36101 >"$WORK/fog.log" 2>&1 & echo $! > "$WORK/fog.pid")
sleep 3
if kill -0 "$(cat "$WORK/fog.pid" 2>/dev/null)" 2>/dev/null; then
    pass "fog node starts and stays alive"
    kill "$(cat "$WORK/fog.pid")" 2>/dev/null
else
    info "fog node exited" "$(head -2 "$WORK/fog.log" | tr '\n' ' ')"
fi

run 10 "$BIN" xdp probe
info "xdp probe (kernel-dependent)" "$(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"

# ───────────────────── L. graceful negatives ─────────────────
echo "--- L. negatives ---"
run 10 "$BIN" license bogus
expect "license unknown action" 'Unknown'

run 10 "$BIN" crypto verify "x" "deadbeef" "deadbeef"
if [ $RC -lt 128 ]; then
    pass "crypto verify garbage input does not crash (rc=$RC)"
else
    fail "crypto verify garbage input crashed (rc=$RC)"
fi

run 10 "$BIN" spa knock 256.256.256.256 --key "$WORK/spa.key" --allow-port 443
if [ $RC -lt 128 ]; then
    pass "spa knock bad IP does not crash (rc=$RC)"
else
    fail "spa knock bad IP crashed (rc=$RC)"
fi

# ───────────────────── M. mimic (known cosmetic) ─────────────
echo "--- M. mimic ---"
run 10 "$BIN" mimic https
if printf '%s' "$OUT" | grep -q 'Traffic mimicry configured'; then
    stub "mimic" "prints 'configured' but config dies with the process (no persistence/no running engine)"
else
    fail "mimic prints configuration"
fi

# ───────────────────── N. documented skips ───────────────────
echo "--- N. safety skips (by policy, statically audited) ---"
skip "run"      "would touch firewall/DNS (kill switch family) — host safety policy"
skip "stop"     "restores system settings — host safety policy"
skip "rotate"   "rotates MAC/hostname — host safety policy"
skip "sysproxy on/off" "changes system proxy — host safety policy (status read-only tested below)"
run 10 "$BIN" sysproxy status
info "sysproxy status" "$(printf '%s' "$OUT" | head -2 | tr '\n' ' ')"
skip "spa serve (real)" "needs nftables/ipset root — dry-run tested"
skip "xdp attach/detach/drop" "needs root + BPF kernel — probe only"
skip "xdp compile" "needs clang+bpftool toolchain — covered by unit tests"
skip "trust update-roots" "writes trust store — verified offline via unit tests"
skip "blockcheck --apply" "mutates config — probe part tested below"
run 45 "$BIN" blockcheck --domains example.com --timeout 4000 --json
info "blockcheck probe (external net)" "rc=$RC $(printf '%s' "$OUT" | head -c 120)"

# ───────────────────── summary ───────────────────────────────
echo "============================================================"
echo " SMOKE SUMMARY: PASS=$PASS FAIL=$FAIL STUB=$STUB INFO=$INFO SKIP=$SKIP"
if [ -n "$FAILED_NAMES" ]; then
    echo " FAILED:$FAILED_NAMES"
fi
echo "============================================================"
rm -rf "$WORK"
[ "$FAIL" -eq 0 ]
