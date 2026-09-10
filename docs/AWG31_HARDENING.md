# AWG 3.1 Hardening + Scoped Trust (v1.7.0)

Adaptation of AmneziaWG 3.1 anti-classifier techniques for NCP transports,
plus scoped trust containment for state root CAs (NUЦ) and a one-command
server installer.

---

## 1. Header protection (`ncp_header_protection`)

**Problem.** NCP transports used static magic prefixes — `PH`
(port-hopping), `FOG` (fog mesh), `RS` (AEMM shards). Two/three constant
bytes at a fixed offset are a ready-made DPI signature.

**Solution (AWG 3.1 style).** The magic is replaced by a session-derived
prefix:

```
prefix(tag) = HKDF-SHA256(secret, salt="ncp-hp-v1",
                          info=context || tag_u64_BE)[0..N)
```

- `secret` — shared session secret (per installation);
- `context` — protocol separation (`ncp-ph`, `ncp-fog`, `ncp-aemm`);
- `tag` — a frame field at a fixed offset (epoch for port-hopping, seq
  for fog, block_id for AEMM). The receiver parses the fields
  optimistically, then verifies the prefix in **constant time**
  (`sodium_memcmp`). Tampering with the tag breaks the prefix.

HKDF is implemented over libsodium HMAC-SHA256 (compatible with
libsodium ≥ 1.0.18; `crypto_kdf_hkdf_*` is not required). RFC 5869 test
vectors are covered by unit tests.

### Usage

```bash
# port-hopping, both sides:
ncp porthop serve  --base-port 40000 --range 16 --secret <hop-secret> \
    --hp-secret <hp-secret> ...
ncp porthop client --host <ip> --base-port 40000 --range 16 \
    --secret <hop-secret> --hp-secret <hp-secret> --message "ping"

# fog mesh (all nodes share the same secret):
ncp fog node --id <hex32> --port 9999 --frame-secret <mesh-secret>
```

AEMM: `aemm::pack_shard_hp()` / `aemm::unpack_shard_hp()` take a
`HeaderProtection` instance; legacy `pack_shard()`/`unpack_shard()` are
unchanged.

## 2. Version-range randomisation (AWG H1–H4 analogue)

The frame version byte is drawn at random (CSPRNG) from a
per-installation range; the receiver accepts any value inside it:

```bash
ncp porthop serve ... --ver-range 100-140
ncp fog node ...    --ver-range 100-140
```

No constant byte remains in the header → no universal DPI rule.

## 3. Content padding (AWG ContentPaddingAddition analogue)

```bash
ncp porthop serve/client ... --content-padding 2-10
```

Appends `pad_len` CSPRNG bytes + 1 length byte to every datagram
(`PH_FLAG_CONTENT_PADDING`), breaking the 16-byte-multiple patterns that
statistical classifiers look for. Minimal recommended value under
bandwidth pressure: 2–10 bytes.

## 4. Timers as ranges

`--hop-interval` accepts a range (`30-120`); the actual interval is
re-sampled per epoch. The reusable primitive is
`ncp::TimerRange` (`ncp_timer_range.hpp`, header-only) — drop-in for any
protocol timer constant (keepalive, rekey, timeouts).

## 5. CPS chains (AWG I1–I5 analogue, active-probing defence)

Fake "signature" packets are sent before the real handshake, so a DPI
replay/fingerprint of the flow start sees benign protocols:

```bash
# standalone
ncp cps test --chain "dns:yandex.ru;wait:20-80;quic;tls:mail.ru"
ncp cps send --host <ip> --port <n> --chain "..." [--proto udp|tcp]

# before a porthop session
ncp porthop client ... --cps "dns:yandex.ru;wait:20-80;quic"
```

Chain language (`;`-separated steps):
`dns:<domain>` · `quic[:<sni>]` · `tls:<domain>` · `hex:<bytes>` ·
`wait:<ms|min-max>`.

## 6. Scoped trust for state roots (NUЦ containment)

**Threat model.** A state root CA in the *system* store can issue trusted
certificates for any domain — silent MITM of everything, with no
Certificate Transparency coverage for locally installed roots.

**Strategy.** The state root lives only inside the NCP process and
applies only to whitelisted RU domains; the system store stays clean.

```bash
ncp trust policy-test --host gosuslugi.ru      # CUSTOM (in-process root)
ncp trust policy-test --host google.com        # PUBLIC (system roots)
ncp trust init-ca --out ncp-local-ca           # per-install local CA
ncp trust verify --host bank.ru --chain leaf.pem --roots nuc.pem
ncp trust update-roots --file nuc.pem --sha256 <hex> --sig <b64> \
    --pubkey <b64> --dest roots.pem            # verified auto-update
```

- Default rules: `.ru`, `.su`, `.рф` (`.xn--p1ai`) + well-known bank/gov
  domains; custom rules file via `--rules` (one per line, `#` comments).
- `verify_peer_chain()`: custom-scope hosts validate against the
  in-process store (public fallback keeps publicly-issued sites working);
  all other hosts validate against the system public roots only.
- Every custom-scope validation emits a `custom_root_validation` event
  (GUI event feed hook via `set_event_callback`).
- Root bundle updates require a SHA-256 pin + Ed25519 signature (same
  mechanism as NCP release updates); the bundle is written atomically
  with mode 0600.

**Never** disable TLS verification globally or install the state root
into the system store.

## 7. Server auto-installer (`deploy/`)

```bash
cd deploy
sudo ./install.sh
```

Brings up (Docker Compose): AmneziaWG 3.1 (userspace `amneziawg-go`,
built from source) + `ncp reality` + `ncp spa` + `ncp porthop` with all
the hardening above. Every install regenerates all keys, AWG H1–H4/S1–S4/
Jc/Jmin/Jmax/HeaderProtectionKey, porthop secrets, version ranges and
ports — see `deploy/README.md`. `sudo ./uninstall.sh` removes everything.

## Tests

`test_awg31_hardening.cpp` (25 tests): RFC 5869 HKDF vectors, prefix
derivation/tamper/wrong-secret, version ranges, padding roundtrip, timer
ranges, porthop/fog/aemm integration, CPS builders.
`test_scoped_trust.cpp` (6 tests): policy matching incl. suffix-spoof
resistance, local CA + scoped verification with a real signed leaf,
event feed, verified update accept/reject paths.
