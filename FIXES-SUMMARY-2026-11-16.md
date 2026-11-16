# Fix Summary — 2026-11-16

Thirteen commits on `fix/r17-findings`, produced by running the project and
verifying observed behaviour against a live network rather than reading code.
Every claim below was reproduced before and after the change.

**Final state**: `ctest -C Release` → **8/8 tests pass, 0 failed** (100%).
`ncp_tests` → 1277 tests ran, 1269 passed, 8 skipped, 0 failed.

---

## Real defects fixed

### 1. `blockcheck` was completely non-functional — `FIX-blockcheck-clienthello.md`

`BlockChecker::build_client_hello()` declared three extension lengths that did
not match the bytes it wrote. **Every** real TLS server rejected the hello with
a fatal `decode_error`, so all 14 strategies failed on every domain, always.
`ncp blockcheck` could never select a strategy, and `geneva_fitness` shared the
same builder and was equally broken.

| Extension | Declared | Correct |
|---|---|---|
| `supported_groups` `0x000A` | 6 | 6 + list prefix `4` |
| `signature_algorithms` `0x000D` | 8 | 10 |
| `key_share` `0x0033` | ext 36 / shares 34 | ext 38 / shares 36 |

Byte-level proof against `example.com:443`: shipped → `15 03 01 00 02 02 32`
(fatal alert 50, `decode_error`); corrected → `16 03 03 00 5a 02`
(`ServerHello`). After: `best_strategy: "direct", best_validated: true`.

**This is the headline finding.** The feature could never have worked.

### 2. `sysproxy --port 0` corrupted system proxy settings — `FIX-sysproxy-port-validation.md`

Accepted any integer, cast to `uint16_t`, wrote it to HKCU WinINET. Reproduced
live: `ProxyEnable=1 ProxyServer=127.0.0.1:0`, reported as success, breaking
every proxy-aware application. Recoverable only because `sysproxy off` honours
its save-before-write contract. Now rejected before `sysproxy_apply` runs.

### 3. Port options silently truncated — `FIX-port-truncation-sweep.md`

Same class at four more sites. `proxy --port -1` bound **65535**;
`proxy --port 0` bound an **unpredictable ephemeral port**. All reported
success. The casts were added to silence C4244 — the warning was correct, and
silencing it hid the missing range check.

### 4. CLI returned exit 0 on every failure — `FIX-cli-exit-codes.md`

`main` already returns `g_exit_code`, but only `handle_mimicry_catalog` ever set
it. Unknown commands, invalid args, unreachable hosts, invalid licenses: all
printed an error and exited **0**, so any script saw success.

Fixed across 25 sites: unknown-command dispatch, `autopilot learn` failure,
`sysproxy`, `license info`/`validate`, `import-zapret`, and **all 20**
`*_print_usage()` error sites. Insertion verified as exactly 20 added lines and
0 removed. The 8 `--help`/empty-args sites were deliberately left at exit 0.

### 5. `get_stats()` always returned zeros on Windows — `FIX-network-stats-windows.md`

The `/proc/net/dev` fallback sat inside `#ifndef _WIN32`, so Windows fell
through to the never-populated `stats_`. Added an `#else` branch using
`GetIfTable2` (`iphlpapi` was already linked). Now reports real moving counters.

### 6. `crypto random <n>` ignored the documented argument — `FIX-crypto-random-argument.md`

Always emitted 32 bytes regardless of the count; only the undocumented `-n`
worked. Invalid input now errors instead of silently returning the wrong length.

### 7. porthop printed a blank host — `FIX-porthop-echo-output.md`

`Echo from :59327` — a local ephemeral port after a bare colon, no host.
Misleading: reads as address-resolution failure. Now
`Echo from 127.0.0.1:40000 (local port 59652)`.

### 8. README version three releases stale — `FIX-readme-version-stale.md`

Both READMEs declared 1.7.0; `CMakeLists.txt` (the documented source of truth)
and the binary said 1.7.6. Declaration lines corrected; 1.7.0 changelog entries
are historical and left intact.

---

## Test coverage added

### `TEST-clienthello-regression.md`

The ClientHello bug survived because existing tests parse the hello back with
the matching parser — both sides shared the wrong numbers and agreed. Added two
structural tests that check the tiling arithmetic instead. **Verified to fail on
the original bug** (`extension 10 list length mismatch`) by temporarily
reverting the fix, then confirmed passing once restored.

### `test(functional): assert the correct outcome for a blocked live host`

`ncp_functional_check` was the last CTest failure. It turned out **not** to be a
bug: `www.youtube.com` is blocked here at the IP level (TCP connects, TLS never
answers; DoH resolves it to `64.233.162.198` fine, so not DNS). `learn()`
correctly returned false and marked the host degraded — the test asserted
success unconditionally, so correct behaviour was reported as failure.

The test now probes first and requires the matching outcome. Both paths stay
covered without depending on a third-party host:
- reachable → learn must produce a servable record
- blocked → learn must fail, record the host, mark it degraded, and not serve

Result: 70 passed/1 failed → **74 passed/0 failed**, exit 0.

---

## Verification performed

Exercised against the live binary, not just compiled:

| Module | Result |
|---|---|
| `proxy` | SOCKS5 **and** HTTP CONNECT → real HTTPS, both `200` |
| `crypto` | keygen, sign/verify roundtrip, tamper rejection (`INVALID`) |
| `blockcheck` | selects + validates `split-1`; correctly reports blocked hosts |
| `autopilot` | learn on reachable hosts; degraded marked on blocked |
| `porthop` | live loopback ACK + echo roundtrip |
| `stegodns` | encode→decode roundtrip; wrong passphrase and wrong key both rejected |
| `trust` | RU domain → CUSTOM root, other → PUBLIC (scoping correct) |
| `spa` / `cps` / `fog` / `reality` / `mimic` | validation and error paths |
| `dpi` | WinDivert handle opens; driver `WinDivert64.sys` confirmed RUNNING |

On the WinDivert `error=5` finding from the earlier session: it did not
reproduce. The driver loads and `dpi` reports `WinDivert handle opened
successfully`. Access-denied on open is what non-elevated WinDivert returns by
design, so that "gap" was likely an elevation artifact.

---

## Deliberately not changed

- **`AUDIT.md`, `plan.md`, `web/static/version.txt`** — another session's
  uncommitted work. Left in the working tree untouched; never staged into my
  commits.
- **`get_stats()` has no unit test**, still. Documented gap.
- **CLI argument parsing has no tests** across the board — the common thread
  behind fixes 3, 4, 6 and 7. Handlers return `void`, so `g_exit_code` is the
  only channel and silent success is the default. Making handlers return `int`
  is the durable fix; not done here.
- **Live probe not in CI** — depends on outbound network access, which is why
  it lives in a separate binary.
- **`porthop`/`fog`/`reality`/`i2p`/`xdp`** — only arg handling and unit tests
  verified; no multi-node or Linux-only paths exercised.

---

## Environment note

The `sysproxy` defect (#2) was reproduced against the real HKCU Internet
Settings of this machine. `ncp sysproxy off` restored the original values
(`ProxyEnable=0`, empty `ProxyServer`), verified after. Final state: inactive.

## Reproducing

```bash
cmake --build . --config Release --target ncp-cli ncp_tests ncp_functional_check
ctest -C Release                    # 8/8 pass
ncp blockcheck --domains example.com --timeout 5000   # selects a strategy
ncp --version                       # v1.7.6
```

Build note: `cmake` is not on the bash `PATH` here. It lives at
`C:/Program Files/Microsoft Visual Studio/18/Insiders/Common7/IDE/CommonExtensions/Microsoft/CMake/CMake/bin/cmake.exe`.
CLI target is `ncp-cli`, not `ncp`.
