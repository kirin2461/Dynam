# Fix: README version declarations were three releases stale

**Date**: 2026-11-16
**Files changed**: `README.md`, `README.ru.md` (3 lines each)
**Status**: Fixed. Documentation-only — no code or binary change.

---

## Summary

The project's version declarations disagreed with each other. The build system
and the shipped binary said **1.7.6**; both READMEs said **1.7.0**:

| Source | Version |
|---|---|
| `CMakeLists.txt` → `project(ncp-cpp VERSION ...)` | `1.7.6` |
| `ncp --version` | `ncp v1.7.6` |
| `README.md` (status, CMake line, footer) | `1.7.0` |
| `README.ru.md` (status, CMake line, footer) | `1.7.0` |

`CMakeLists.txt` is explicitly the single source of truth — the comment at line
49 says so, and `ncp_version.h` is generated from `project(VERSION)`. The READMEs
were simply never updated alongside the last three version bumps.

## What changed

Three declaration lines in each file:

```diff
 ## Current Status

-**Version**: 1.7.0
-**CMake Version**: 1.7.0 (synced)
+**Version**: 1.7.6
+**CMake Version**: 1.7.6 (synced)
```

```diff
 **Last Updated**: October 31, 2026
-**Version**: 1.7.0
+**Version**: 1.7.6
```

Equivalent changes in `README.ru.md` (`**Версия**`, `**Версия CMake**`).

## What was deliberately NOT changed

Both READMEs contain changelog entries that legitimately reference 1.7.0:

```
### What's new in 1.7.0 — AWG 3.1 hardening + NUЦ scoped trust + auto-installer
- **v1.7.0 — AWG 3.1-style header protection.** ...
```

These are historical release notes for a specific past version. Rewriting them
to 1.7.6 would be wrong — they describe what shipped in 1.7.0, and that did not
change. Only the "current version" declarations were corrected. The same
reasoning applied to `README.ru.md`'s "Что нового в 1.7.0".

## Verification

All four sources now agree:

```
$ grep -n "VERSION 1\." CMakeLists.txt
3:    VERSION 1.7.6

$ ncp --version
ncp v1.7.6

$ grep -n "^\*\*Version\*\*\|^\*\*CMake Version\*\*" README.md
9:**Version**: 1.7.6
10:**CMake Version**: 1.7.6 (synced)
649:**Version**: 1.7.6

$ grep -n "^\*\*Версия\*\*" README.ru.md
9:**Версия**: 1.7.6
644:**Версия**: 1.7.6
```

Diff is minimal and contained — `git diff --numstat` reports `3 3` for each
file, so no unintended rewrites and no line-ending churn (both READMEs are CRLF
in the working tree and were preserved that way).

Changelog history confirmed untouched:

```
$ sed -n '28p;30p' README.md
### What's new in 1.7.0 — AWG 3.1 hardening + NUЦ scoped trust + auto-installer
- **v1.7.0 — AWG 3.1-style header protection.** The static frame magics
```

## Why it matters

Low severity, but it is the kind of inconsistency that misleads users into
filing bugs against the wrong version, and it makes release notes hard to trust:
a README claiming 1.7.0 next to a binary reporting 1.7.6 invites the reader to
wonder which is authoritative. The fix costs nothing and removes that ambiguity.

## Preventing recurrence

The version is bumped in `CMakeLists.txt` alone (per the "single source of truth"
comment), and nothing propagates it to the READMEs. A CI check comparing the
`project(VERSION)` value against the README declarations would catch drift at the
next bump. Not added here — noted as a follow-up.
