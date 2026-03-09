# NCP C++ — Patch & Security Fix Log

Chronological record of security patches, hardening passes, and CI fixes.

---

## Phase 0 — CSPRNG Migration (2026-02-19)

**Goal**: Eliminate every `std::mt19937` / `std::random_device` usage across the
codebase and replace with cryptographically secure alternatives (libsodium
`randombytes_*` or the new `ncp::CSPRNG` wrapper).

**Why**: `mt19937` is a Mersenne Twister — fast, but **not** cryptographically
secure.  An attacker who observes 624 consecutive 32-bit outputs can reconstruct
the full internal state and predict every future value.  In a DPI-evasion tool
this means predictable padding, predictable timing jitter, and predictable
identity rotation — all of which a TSPU/DPI system can exploit.

### New file: `ncp_csprng.hpp` (header-only)

Unified CSPRNG API backed by libsodium:

| Function | Replaces |
|---|---|
| `CSPRNG::random_bytes(n)` | `randombytes_buf` |
| `CSPRNG::uniform_uint32(upper)` | `std::uniform_int_distribution` |
| `CSPRNG::uniform_double(min,max)` | `std::uniform_real_distribution` |
| `CSPRNG::fill_random(vec)` | manual byte loops |
| `CSPRNG::shuffle(vec)` | `std::shuffle(mt19937)` |

Legacy C-style wrappers (`ncp::csprng_init`, `csprng_fill`, `csprng_range`,
`csprng_byte`, `csprng_double`, `csprng_double_range`) preserved for modules
that already migrated to them.

### Commits (chronological)

| # | Commit | Module | mt19937 removed |
|---|---|---|---|
| 0.1 | `da3e629` | `ncp_adversarial` | HPP+CPP: rng\_, distributions |
| 0.2 | `5db2c60` | `ncp_flow_shaper` | HPP+CPP: 16 replacement sites |
| 0.3 | `601a1f7` | `ncp_security` | HPP+CPP: TrafficPadder rng\_ |
| 0.4 | `91cae71` | `ncp_mimicry` | HPP+CPP: 20+ replacement sites |
| 0.5 | `84612ee` | `ncp_dpi_advanced` | HPP: shuffle\_segments param |
| 0.6 | `4af41b0` | `ncp_spoofer` + `dhcp_spoofer` | HPP+CPP: generate\_random() |
| 0.7 | `c47d4fe` | `ncp_entropy_masking` | HPP+CPP: new impl file |
| 0.8 | `ce130dc` | `ncp_geneva_engine` | HPP+CPP: tamper/disorder |
| 0.9 | `e42acd3` | `ncp_probe_resist` | HPP: dead rng\_ removed |
| 0.10 | `4bcea41` | `ncp_dummy` | HPP+CPP: 5 replacements |
| 0.11a | `20d4260` | `examples/dpi_advanced_example` | Example mt19937 removed |
| 0.11b | `c1ee08b` | `ncp_timing` + `ncp_identity` | CPP: Box-Muller, Fisher-Yates |

**Result**: 0 occurrences of `std::mt19937` remain in `src/` or `examples/`.

---

## Phase 1 — CI/CMake Fixes (2026-02-19)

Commit: [`a999cf1`](https://github.com/kirin2461/Dynam/commit/a999cf157f9750b34d59d5d36a7e72e70363a843)

### Changes

| File | Fix |
|---|---|
| `src/core/CMakeLists.txt` | Add `ncp_csprng.hpp` and `ncp_thread_pool.hpp` to `NCP_CORE_INCLUDE_HEADERS` |
| `tests/test_csprng.cpp` | **NEW** — 18 unit tests for `ncp::CSPRNG` |
| `tests/CMakeLists.txt` | Register `test_csprng.cpp` |
| `.github/workflows/build.yml` | Fix Windows `if: false` YAML syntax; add `libssl-dev`; `ENABLE_WEBSOCKETS=OFF` |
| `.github/workflows/ci.yml` | Remove Qt6 from non-GUI builds; remove `libwebsockets`; `ENABLE_WEBSOCKETS=OFF` |

---

## Earlier Patches (2026-02-12)

### Issues #2, #3, #4 — DPI Bypass Security Fixes

Three critical/medium security issues patched:

- **Issue #2**: Config race condition in proxy threads — fixed with config snapshot per connection
- **Issue #3**: Blocking `accept()` prevents responsive shutdown — fixed with `select()`/`SO_RCVTIMEO` timeout
- **Issue #4**: Fake ClientHello easily detectable — fixed with 17 cipher suites, 32-byte session ID, GREASE values, 5 critical extensions

**Files modified**: `ncp_dpi.cpp`, `dpi_advanced.cpp`  
**Tests added**: 7 integration tests in `tests/integration/`  
**Full guide**: [Issue #16](https://github.com/kirin2461/Dynam/issues/16)

### Testing

```bash
cd build
ctest --output-on-failure -C Release
```

Expected: all tests pass including `CSPRNGTest.*` suite (18 tests).

### Sanitizer runs

```bash
# ASan
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON \
  -DCMAKE_CXX_FLAGS="-fsanitize=address -fno-omit-frame-pointer"
cmake --build . && ctest --output-on-failure

# TSan
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON \
  -DCMAKE_CXX_FLAGS="-fsanitize=thread"
cmake --build . && ctest --output-on-failure

# UBSan
cmake .. -DCMAKE_BUILD_TYPE=Debug -DENABLE_TESTS=ON \
  -DCMAKE_CXX_FLAGS="-fsanitize=undefined"
cmake --build . && ctest --output-on-failure
```

---

## Verification Checklist

- [ ] `grep -rn 'mt19937' src/ examples/` returns 0 results
- [ ] `ncp_csprng.hpp` is in `install(DIRECTORY include/ ...)`
- [ ] `test_csprng.cpp` passes all 18 tests
- [ ] CI build.yml Linux Release/Debug green
- [ ] CI build.yml macOS Release green
- [ ] CI ci.yml sanitizers (asan/tsan/ubsan) green
- [ ] Config race test passes with 100+ concurrent updates
- [ ] Shutdown completes in <500ms
- [ ] Fake ClientHello has 15+ cipher suites + GREASE

---

For questions, open a [GitHub Issue](https://github.com/kirin2461/Dynam/issues).
