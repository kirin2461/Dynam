# Fix: NetworkSpoofer audit findings (R18-01 … R18-09) + R17-10

**Date**: 2026-11-16
**Files changed**: `src/core/src/spoofer.cpp`,
`src/core/include/ncp_spoofer.hpp`, `src/cli/main.cpp`,
`src/core/src/ncp_connection_director.cpp`, `tests/test_spoofer.cpp`,
`tests/test_spoofer_safety.cpp` (new), `tests/CMakeLists.txt`
**Source**: `AUDIT.md` R18-01…R18-09, R17-10
**Status**: Fixed, built, test suite green. **Not all paths executed** — see
the limitations section, which matters here.

---

## R18-01 — disk-serial spoof corrupted the disk enumeration key (High)

**Problem.** `apply_disk_serial` wrote a generated value into value `"0"` of
`HKLM\SYSTEM\CurrentControlSet\Services\disk\Enum`. That value holds the first
enumerated disk's **device instance path** (`SCSI\Disk&Ven_…`), not a serial.
The write achieved nothing for the real serial (which comes from the drive's
IDENTIFY data) while corrupting the enumeration list for every program that
reads it — and it was never restored.

**Fix.** The write is removed. The function reports "not supported" on all
platforms, because a disk serial cannot be changed from user mode.

## R18-02 — `apply_hw_info` was a no-op reporting success (Medium)

**Problem.** Windows branch was `return true;`. `status.hw_info_spoofed` became
true and the user was told hardware info had been spoofed when nothing happened.

**Fix.**

```cpp
bool NetworkSpoofer::apply_hw_info(const std::string& serial) {
    if (serial.empty()) return false;
    // R18-02: hardware serials are read from firmware (SMBIOS/DMI) or the
    // disk's identify page. Neither can be changed from user mode…
    (void)serial;
    return false;
}
```

## R18-03 — SMBIOS spoof was cosmetic and partly wrong (Medium)

**Problem.** Windows wrote `HKLM\HARDWARE\DESCRIPTION\System\BIOS`, which is
rebuilt from firmware at every boot, and put the generated UUID into
`SystemProductName` (the product-name field).

**Fix.** Stop writing the UUID into `SystemProductName`; mark Windows as
not-supported. The Linux `smbios_hook.cpp` `LD_PRELOAD` path is per-process and
is documented as such rather than presented as a system-wide change.

## R18-04 — incomplete restore (Medium)

**Problem.** `restore_original_identity()` restored only MAC, IPv4, DNS and
hostname. IPv6, hw-info, SMBIOS, disk serial, DHCP client ID and TCP fingerprint
were never undone. A partial `enable()` failure left changes behind.

**Fix.** A change journal records `(what, original, applied)` for every applied
change and unwinds them in reverse on `disable()`:

```cpp
// ==================== Restore journal (R18-04) ====================
void NetworkSpoofer::journal_record(JournalEntry what, const std::string& original,
                                    const std::string& applied) {
    journal_.push_back({what, original, applied});
}

void NetworkSpoofer::journal_clear() { journal_.clear(); }
```

A rotation replaces the *applied* value but keeps the *original*, so restoring
after several rotations still returns to the pre-spoof state.

## R18-05 — DHCP client ID spoof did not work (Medium)

**Problem.** Windows ran `netsh … dhcpclientid=<id>`; `dhcpclientid` is not a
valid `netsh` parameter, so it silently did nothing. Linux edited
`dhclient.conf` and restarted `dhclient`, which most current distributions do
not run.

**Fix.** Windows returns false (no supported way to set option 61). Linux
detects NetworkManager / systemd-networkd first and refuses **with a reason**
instead of editing a file that is ignored.

## R18-06 — dangerous library defaults (Medium)

**Problem.** `SpoofConfig` defaulted `spoof_ipv4/ipv6/mac/dns/hw_info/
disk_serial/dhcp_client_id` to `true`. The CLI overrides them, but any other
caller using `SpoofConfig{}` (GUI, tests, future code) got network-breaking
changes.

**Fix.** Every field now defaults to `false`:

```cpp
bool spoof_ipv4 = false;
bool spoof_ipv6 = false;
bool spoof_mac = false;
bool spoof_dns = false;
bool spoof_hw_info = false;
bool spoof_hostname = false;
bool spoof_disk_serial = false;        // (not supported)
bool spoof_dhcp_client_id = false;     // (not supported)
```

**Behaviour-preservation check.** Verified `src/cli/main.cpp` sets each field
explicitly (`main.cpp:1619-1622` for defaults, `1649-1651` for `--full-spoof`),
so `ncp run` behaves as before. `--full-spoof` no longer enables the three
categories that cannot work.

## R18-07 — IPv4 spoof/restore lost mask, gateway and DHCP mode (Low)

**Problem.** Spoof and restore both hard-coded `/24`, and a DHCP-assigned
address was restored as a static one.

**Fix.** Capture the on-link prefix length and DHCP flag before changing:

```cpp
// R18-07: keep the mask and prefix so a restore does not fall
// back to a hard-coded /24.
uint8_t plen = ua->OnLinkPrefixLength;
if (plen >= 8 && plen <= 30)
    original_identity_.ipv4_netmask = prefix_to_netmask(plen);
…
// R18-07: remember whether the address came from DHCP, so restore puts
// the adapter back on DHCP instead of pinning a stale lease as static.
original_identity_.ipv4_dhcp = (addr->Flags & IP_ADAPTER_DHCP_ENABLED) != 0 || …
```

## R18-08 — TCP fingerprint changes were global and unrestored (Low)

**Problem.** Windows wrote `TcpWindowSize` (ignored since Vista auto-tuning) and
`TcpMaxSegmentSize` on the `Interfaces` *parent* key (applies to no interface).
Linux changed the interface MTU. Nothing was restored.

**Fix.** Both ineffective Windows writes removed, leaving only `DefaultTTL`
(which does have an effect) — and it is journaled for restore. The MTU change
is dropped.

## R18-09 — success detected by searching output for `"Error"` (Low)

**Problem.** Every `apply_*` used `result.find("Error") == npos`. On
non-English Windows (this machine's is Russian) `netsh`/`reg` print localized
messages, so failures were reported as success.

**Fix.** `execute_command_safe` populates `exit_code` from the child's exit
status and success is `exit_code == 0`:

```cpp
struct CommandResult {
    int exit_code = -1;   // -1 = could not start
    bool ok() const { return exit_code == 0; }
};
```

Verified: no `find("Error")` remains in `spoofer.cpp`.

## R17-10 — per-tick stats rebuild (efficiency)

**Problem.** Every `poll()` rebuilt a fresh `unordered_map` of `stats()`
snapshots for every session and called `refresh_gates()` under `req_mutex`,
even when nothing had changed — on the data-path hot loop, at up to ~40 Hz.

**Fix.** Publish only on change, tracked by three flags that flip on handshake
completion and profile transitions, with a snapshot buffer compared against the
last published one.

## Verification

Build clean; test suite green:

```
[==========] 1283 tests from 161 test suites ran.
[  PASSED  ] 1275 tests.
[  SKIPPED ] 8 tests.
```

`ctest -C Release` → **8/8 passed, 0 failed**.

Six new tests were added (`tests/test_spoofer_safety.cpp`, plus additions to
`test_spoofer.cpp`), which is why the total went 1277 → 1283.

Code-level checks performed:

| Item | Verified by |
|---|---|
| R18-01 | read: write removed, returns false with rationale |
| R18-02 | read: Windows branch returns false |
| R18-04 | read: journal_record/journal_clear defined and called |
| R18-05 | read: Windows returns false; Linux detects NM/systemd-networkd |
| R18-06 | read + grep: all defaults false; CLI sets each explicitly |
| R18-07 | read: prefix length + DHCP flag captured |
| R18-08 | read: ineffective writes removed, DefaultTTL journaled |
| R18-09 | grep: no `find("Error")` left; exit_code populated from child |
| R17-10 | read: change-detection flags + last_snapshot comparison |
| R19-01/02/03 | **executed**: see `FIX-cli-help-safety.md` |

## Limitations — read before merging

- **The spoofing paths were never executed.** `ncp run` requires a valid license,
  which this machine does not have, so `enable()`/`disable()`/the restore
  journal were verified by reading only. The unit tests exercise the spoofer
  classes directly and pass, but no live `--full-spoof` cycle was performed.
  A real test — enable full spoof, confirm the journal, `ncp stop`, confirm
  every change is reverted — is still outstanding.
- **No live network was changed during this work.** Nothing here was proven by
  observing an adapter.
- The atomic/persistent form of the restore journal (surviving a crash, plus an
  `ncp spoof restore` command) as described in the audit's fix direction was
  **not** implemented — the journal is in-memory for the process lifetime.
