# Fix: CLI returned exit code 0 on every failure

**Date**: 2026-11-16
**File changed**: `src/cli/main.cpp` (`g_exit_code` set on error paths, +9 lines)
**Status**: Fixed, rebuilt, verified. No test regressions.

---

## Summary

`ncp` exited `0` for every error it reported. Unknown commands, invalid
arguments, unreachable hosts — all of them printed an error message and then
returned success:

```
$ ncp definitelynotacommand
Unknown command: definitelynotacommand
$ echo $?
0
```

A message on stderr plus a zero exit status is the worst combination for
automation: anything scripting `ncp` sees success and proceeds as though the
command worked.

## Root cause

`main` already returns a global:

```cpp
static int g_exit_code = 0;   // line 169
...
    parser.parse_and_execute(argc, argv);
    return g_exit_code;       // line 1104
```

The wiring is there. The problem is that **only one handler ever sets it** —
`handle_mimicry_catalog` (lines 5815-5898). Every other failure path prints to
`std::cerr` and returns `void`, so `g_exit_code` stays `0` and `main` reports
success.

Handlers have signature `std::function<void(const std::vector<std::string>&)>`,
so they cannot return a status. The global is the intended channel; it was just
never used outside that one handler.

Measured before the fix:

| Command | Exit |
|---|---|
| `ncp definitelynotacommand` | 0 |
| `ncp crypto badaction` | 0 |
| `ncp proxy --port -1` | 0 |
| `ncp reality serve --key-file /tmp/nope.key` | 0 |
| `ncp autopilot learn www.youtube.com` (host unreachable) | 0 |
| `ncp sysproxy on --port 0` | 0 |

## The change

Set `g_exit_code = 1` on the failure paths that were provably wrong, using the
existing channel:

1. **Unknown command** — `parse_and_execute`, the dispatch miss.
2. **`autopilot learn` found no working strategy** — the substantive case. It
   prints `[-] No working strategy found ...` and reported success.
3. **`sysproxy on` invalid port** and **`sysproxy_apply` failure** — the
   registry-writing command.
4. **Port validation early-returns** added earlier in this branch (`dpi
   --port`/`--target-port`, `i2p --sam-port`, `proxy --port`).
5. **`license info`** with no valid license file, **`license info --online`
   validation failure**, and **`license validate`** returning `INVALID`.
6. **`import-zapret`** usage error and unreadable `--file`.

```diff
         if (it == commands_.end()) {
             std::cerr << "Unknown command: " << cmd << "\n";
             print_usage();
+            g_exit_code = 1;
             return;
         }
```

```diff
         } else {
             std::cout << "[-] No working strategy found for " << positional
                       << " (host unreachable or IP-level blocked). "
                       << "Marked degraded; background re-learn will retry with backoff.\n";
+            g_exit_code = 1;
         }
         return;
```

Note on the autopilot case: the message is `std::cout`, not `cerr`, because it is
informational rather than an error — the host is marked degraded and background
re-learn retries, which is designed behaviour. The exit code still has to be
non-zero, because a caller asking "did you learn this host?" needs the answer to
be `no`.

## Verification

After the fix, both directions confirmed:

| Command | Exit | Correct |
|---|---|---|
| `ncp definitelynotacommand` | **1** | ✓ |
| `ncp proxy --port -1` | **1** | ✓ |
| `ncp sysproxy on --port 0` | **1** | ✓ |
| `ncp autopilot learn www.youtube.com` (unreachable) | **1** | ✓ |
| `ncp autopilot learn example.com` (reachable) | **0** | ✓ |
| `ncp license info` (no license file) | **1** | ✓ |
| `ncp license validate` (no license file) | **1** | ✓ |
| `ncp import-zapret` (no args) | **1** | ✓ |
| `ncp import-zapret --file /tmp/nope.txt` | **1** | ✓ |

Success paths still exit 0 — checked to make sure the fix did not over-fire:

```
ncp --version          -> 0
ncp status             -> 0
ncp crypto keygen      -> 0
ncp network interfaces -> 0
ncp trust policy-test  -> 0
ncp license hwid       -> 0
```

### Test suite — no regressions

```
[==========] 1275 tests from 159 test suites ran. (52963 ms total)
[  PASSED  ] 1267 tests.
[  SKIPPED ] 8 tests.
```

Identical to baseline. The 8 skips are `I2PManagerTest.*` (no I2P SAM bridge on
`127.0.0.1:7656`), environmental.

## Scope: the full sweep

The first batches fixed only the paths that had been demonstrated. A survey then
found the same missing assignment at **20 usage-error sites across 9 handlers** —
every `*_print_usage()` call preceded by a `std::cerr` and not followed by
`g_exit_code = 1`.

All 20 are now fixed. The insertion was verified as exactly 20 added lines and 0
removed (`git diff --numstat` → `20 0`), so no logic moved.

The distinction that mattered during the sweep: `print_usage()` is called from
**two** very different contexts, and only one is an error.

```cpp
// Help request — NOT an error, must stay exit 0
if (args.empty() || has_flag(args, "--help") || has_flag(args, "-h")) {
    cps_print_usage();
    return;
}

// Real error — must be exit 1
if (spec.empty()) {
    std::cerr << "[!] cps requires --chain \"<spec>\"\n";
    cps_print_usage();
    return;
}
```

Sites were classified by whether `std::cerr` appeared in the preceding lines.
The 8 `--help`/empty-args sites were deliberately left alone; the 20 error sites
were fixed. Both were then verified independently (see below).

### Verified after the sweep

Error paths — all now exit 1:

```
cps bogusaction        -> 1     fog bogusaction      -> 1
stegodns bogusaction   -> 1     porthop bogusaction  -> 1
trust bogusaction      -> 1     reality bogusaction  -> 1
xdp bogusaction        -> 1     spa bogusaction      -> 1

cps test (no --chain)  -> 1     porthop serve (no args) -> 1
fog node (no args)     -> 1     reality serve (no args) -> 1
```

Help paths — all still exit 0:

```
cps --help  stegodns --help  trust --help  spa --help  fog --help
porthop --help  reality --help  xdp --help  import-zapret --help
mimicry-catalog --help      -> all 0
```

A bare `ncp <cmd>` with no arguments also exits 0, because it hits the
`args.empty()` help branch by design — that was checked explicitly after the
first verification pass appeared to show usage errors still exiting 0, and the
apparent failure turned out to be the *help* path being measured by mistake.

## Design note

The handler signature is `std::function<void(const std::vector<std::string>&)>`,
so a handler cannot return a status. The global is the only channel, which makes
silent success the default — that is why this rotted in the first place. Every
new handler has to remember to set it.

A durable fix would be to return `int` from handlers, or add a `fail()` helper
that prints, sets the code and returns. That is a larger refactor and was not
done here; the 20 sites are corrected individually.

## Why the test suite did not catch this

No test invokes the CLI binary and inspects its exit status. The gtest suite
tests library classes directly; `ncp_functional_check` calls the `AutoPilot` API
rather than the `ncp` executable. Shell-level behaviour — exit codes, stderr,
argument handling — is untested across the board, which is the common thread
through every CLI fix on this branch.

## Note on `ncp_functional_check`

That binary still exits `1` with `[FAIL] live learn youtube.com`. That is
**correct** behaviour, not a regression from this change: `www.youtube.com` is
genuinely unreachable from this machine (curl returns `000`, DNS returns
NXDOMAIN), and the check asserts a live learn must succeed. The assertion itself
is environment-dependent and will fail on any host that cannot reach YouTube.
Worth making that test skip-or-report rather than fail when the host is
unreachable; noted, not changed here.
