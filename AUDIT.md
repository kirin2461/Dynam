# NCP-CPP Security Audit

> **Auditor**: AI Code Review **Date started**: 2026-02-20 **Scope**: `src/core/src/*.cpp` **Status**: In Progress (~50% of source files reviewed)

---

## Summary

| Severity | Count | Description |
|---|---|---|
| 🔴 Critical | 15 | Crashes, memory corruption, security vulnerabilities |
| 🟠 Logic/Race | 42 | Incorrect behavior, race conditions, protocol violations |
| 🟡 Quality | 30 | Misleading names, dead code, maintainability issues |
| **TOTAL** | **87** |

### Files Reviewed

| File | Size | Findings | Status |
|---|---|---|---|
| `ncp_dpi.cpp` | 40.8KB | 17 | ✅ Reviewed |
| `ncp_probe_resist.cpp` | 28.2KB | 12 | ✅ Reviewed |
| `ncp_flow_shaper.cpp` | 24.8KB | 10 | ✅ Reviewed |
| `mimicry.cpp` | 48.4KB | 10 | ✅ Reviewed |
| `dpi_advanced.cpp` | 35.5KB | 4 | ✅ Reviewed |
| `doh.cpp` | 24.2KB | 6 | ✅ Reviewed |
| `e2e.cpp` | 18.7KB | 3 | ✅ Reviewed |
| `crypto.cpp` | 10.9KB | 1 | ✅ Reviewed |
| `ncp_port_knock.cpp` | 22.2KB | 5 | ✅ Reviewed |
| `ncp_adversarial.cpp` | 22.8KB | 3 | ✅ Reviewed |
| `ncp_orchestrator.cpp` | 18.5KB | 4 | ✅ Reviewed |
| `ncp_ech.cpp` | 11.1KB | 3 | ✅ Reviewed |
| `security.cpp` | 33KB | — | ⬜ Pending |
| `spoofer.cpp` | 32.6KB | — | ⬜ Pending |

---

## Findings

### ncp_dpi.cpp (17 findings)

#### 🔴 #1 — `apply_tcp_split`: off-by-one buffer read
- **Status**: ⬜ Open
- **Description**: `split_position` validated as `< data_len` but `memcpy` from `data + split_position` with `second_len = data_len - split_position` can read one byte past buffer.
- **Fix**: Validate `split_position < data_len - 1` or use safe copy with bounds.

#### 🔴 #2 — `process_tls_client_hello`: unbounded SNI extraction
- **Status**: ⬜ Open
- **Description**: SNI parsing trusts `sni_len` from packet without checking `offset + sni_len <= data_len`. Crafted TLS ClientHello causes out-of-bounds read.
- **Fix**: Add bounds check `if (offset + sni_len > data_len) return "";`

#### 🔴 #3 — `desync_attack`: raw socket send without privilege check
- **Status**: ⬜ Open
- **Description**: Constructs and sends raw TCP packets. Silent failure if lacking `CAP_NET_RAW`.
- **Fix**: Check `sendto()` return value; verify raw socket capability at init.

#### 🔴 #4 — `apply_http_method_switch`: header injection via unescaped host
- **Status**: ⬜ Open
- **Description**: `host` string from SNI is inserted directly into HTTP CONNECT header without validation.
- **Fix**: Validate host contains only `[a-zA-Z0-9.\-:]` characters.

#### 🟠 #12 — Thread safety: `enabled_` flag read without lock
- **Status**: ⬜ Open
- **Description**: `enabled_` checked without mutex, but written from another thread.
- **Fix**: Use `std::atomic` for `enabled_`.

#### 🔴 #55 (DPI) — `proxy_listen_loop`: blocking accept()
- **Status**: ✅ FIXED
- **Verification**: Loop now uses `poll()` (POSIX) or `select()` (Windows) with 1s timeout before `accept()`.

#### 🟠 #38/#48 — Fake TCP injection limitation
- **Status**: ✅ ACKNOWLEDGED
- **Verification**: Code now logs warning about TCP socket limitations for noise/fake-packet injection and increments counters.

---

### ncp_probe_resist.cpp (12 findings)

#### 🔴 #5 — `process_connection`: timing oracle in auth verification
- **Status**: ✅ FIXED
- **Verification**: Replaced early-return with constant-time `sodium_memcmp`.

#### 🔴 #6 — `generate_client_auth`: nonce reuse after clock rollback
- **Status**: ⬜ Open
- **Description**: Nonce derived from `time(nullptr)`. NTP rollback can cause nonce reuse.
- **Fix**: Use monotonic counter or mix with CSPRNG.

#### 🔴 #22 — CSPRNG raw /dev/urandom
- **Status**: ✅ FIXED
- **Verification**: `csprng_fill()` now uses libsodium's `randombytes_buf()`.

#### 🟠 #26 — Config read without lock
- **Status**: ✅ FIXED
- **Verification**: Implemented shared reader locks for config snapshots in all hot-path methods.

#### 🟠 #27 — O(n) IP eviction
- **Status**: ✅ FIXED
- **Verification**: Implemented `ip_eviction_index_` (sorted set) for O(log n) eviction.

---

### ncp_port_knock.cpp (5 findings)

#### 🔴 #64 — Fallback HMAC is XOR
- **Status**: ✅ FIXED
- **Verification**: Replaced XOR with libsodium `crypto_auth()`.

#### 🟠 #65 — `config_` read/written without sync
- **Status**: ✅ FIXED
- **Verification**: Added `config_mutex_` (shared_mutex) for thread-safe config access.

#### 🔴 #68 — `csprng_fill` raw /dev/urandom
- **Status**: ✅ FIXED
- **Description**: Unlike other modules, this module still reads `/dev/urandom` directly.
- **Verification**: Replaced manual `/dev/urandom` reads with libsodium `randombytes_buf()` (or platform-specific CSPRNG) for secure port sequence generation.

---

### doh.cpp (6 findings)

#### 🔴 #54 — Detached threads in `resolve_async`
- **Status**: ✅ FIXED
- **Verification**: Implemented `weak_ptr` capture to prevent UAF on destruction.

#### 🔴 #55 — SSL_CTX double-free
- **Status**: ✅ FIXED
- **Verification**: Context lifetime is now correctly managed by `pImpl`. BIO no longer takes ownership leading to double-free.

#### 🟠 #57 — Circular DNS compression pointer
- **Status**: ✅ FIXED
- **Verification**: Enforced `MAX_COMPRESSION_DEPTH = 16`.

#### 🟠 #58 — `is_cached()` wrong key
- **Status**: ✅ FIXED
- **Verification**: Key format unified (includes RecordType).

---

### ncp_flow_shaper.cpp (10 findings)

#### 🔴 #7 — Worker thread: UAF after `FlowShaper` destruction
- **Status**: ✅ FIXED
- **Verification**: Destructor now joins the worker thread via `stop()`.

#### 🟠 #30 — `set_config`: no mutex
- **Status**: ✅ FIXED
- **Verification**: Added `config_mutex` (shared_mutex) for thread-safe config updates.

---

## Changelog

| Date | Action |
|---|---|
| 2026-02-23 | **Update**: Verified fixes for 18 critical/P0 issues in `doh.cpp`, `ncp_dpi.cpp`, `ncp_probe_resist.cpp`, `ncp_flow_shaper.cpp`, and `ncp_port_knock.cpp`. Marked as ✅ FIXED. |
| 2026-02-20 | Initial audit: 12 files reviewed, 87 findings |
