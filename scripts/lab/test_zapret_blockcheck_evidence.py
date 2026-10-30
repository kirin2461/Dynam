#!/usr/bin/env python3
"""Hermetic regression tests for zapret_blockcheck_evidence.sh.

All tests run the wrapper in --self-test (mock) mode or in pure refusal
paths. No test ever invokes the real blockcheck.sh, `ip netns`, or any
firewall command; PATH canaries and a canary blockcheck target prove that.
"""

from __future__ import annotations

import os
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path

LAB = Path(__file__).resolve().parent
WRAPPER = LAB / "zapret_blockcheck_evidence.sh"
ORIGINAL_BLOCKCHECK = Path("/mnt/agents/work/zapret/blockcheck.sh")

MOCK_SUMMARY = """#!/bin/sh
echo '* blockcheck (mock) starting'
echo 'http example.org via 198.51.100.7'
echo '!!!!! AVAILABLE !!!!!'
echo 'UNAVAILABLE code=1'
echo '* SUMMARY'
exit 0
"""

MOCK_NO_SUMMARY = """#!/bin/sh
echo 'mock crashed before summary'
echo 'UNAVAILABLE code=3'
exit 3
"""

MOCK_DIRTY = """#!/bin/sh
echo 'leak 198.51.100.7 and 2001:db8::dead:beef'
echo 'token hunter2secret should vanish'
echo '!!!!! AVAILABLE !!!!!'
echo '* SUMMARY'
exit 0
"""

MOCK_SLEEP = """#!/bin/sh
echo started > "$DYNAM_ZAPRET_MOCK_STARTED"
# exec so the wrapper's cleanup kill hits the sleeper directly (no orphan
# holding the stdout pipe open).
exec sleep 30
"""

CANARY_BLOCKCHECK = """#!/bin/sh
# Must NEVER be executed by self-test mode.
touch "$DYNAM_ZAPRET_CANARY"
exit 0
"""


def make_executable(path: Path, content: str) -> Path:
    path.write_text(content)
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return path


class WrapperCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="dynam-zapret-test-")
        root = Path(self.tmp.name)
        self.lab_dir = root / "lab"
        self.run_dir = root / "run"
        self.bin_dir = root / "bin"
        self.lab_dir.mkdir()
        self.run_dir.mkdir()
        self.bin_dir.mkdir()
        self.marker = self.run_dir / "dynam-zapret-lab.owned"
        self.verdict_file = self.lab_dir / "zapret_blockcheck_verdict.txt"
        self.slog = self.lab_dir / "zapret_blockcheck.sanitized.log"
        self.wlog = self.lab_dir / "zapret_blockcheck_wrapper.log"
        self.rawlog = self.run_dir / "blockcheck.raw.log"

    def tearDown(self):
        self.tmp.cleanup()

    def base_env(self, **extra):
        env = os.environ.copy()
        env["LAB_DIR"] = str(self.lab_dir)
        env["DYNAM_ZAPRET_RUN_DIR"] = str(self.run_dir)
        env.pop("DYNAM_ZAPRET_BLOCKCHECK_OPTIN", None)
        env.pop("ZAPRET_BLOCKCHECK", None)
        env.pop("DYNAM_ZAPRET_ST_NS_STATE", None)
        env.pop("DYNAM_ZAPRET_MOCK_BLOCKCHECK", None)
        env.pop("DYNAM_ZAPRET_REDACT", None)
        env.update(extra)
        return env

    def run_wrapper(self, *args, env=None, timeout=30):
        return subprocess.run(
            ["bash", str(WRAPPER), *args],
            env=env or self.base_env(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )

    def install_mock(self, name: str, content: str) -> Path:
        return make_executable(self.bin_dir / name, content)

    def read_verdict(self) -> dict:
        result = {}
        for line in self.verdict_file.read_text().splitlines():
            key, _, value = line.partition(": ")
            result[key] = value
        return result


class RefusalTests(WrapperCase):
    def test_refuses_without_opt_in(self):
        proc = self.run_wrapper("--self-test")
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("opt-in", proc.stdout)
        self.assertEqual(self.read_verdict()["verdict"], "NOT-RUN")

    def test_refuses_without_isolation_foreign_netns(self):
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="foreign"),
        )
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("ownership marker", proc.stdout)
        self.assertEqual(self.read_verdict()["verdict"], "NOT-RUN")

    def test_refuses_production_netns(self):
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="production"),
        )
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("production", proc.stdout)
        self.assertEqual(self.read_verdict()["verdict"], "NOT-RUN")

    def test_refuses_missing_capabilities(self):
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="create-fail"),
        )
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("CAP_SYS_ADMIN", proc.stdout)

    def test_refuses_non_lab_netns_name(self):
        proc = self.run_wrapper(
            "--opt-in", "--self-test", "--netns", "prod-net",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="missing"),
        )
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("dynam-zapret-", proc.stdout)


class PathSafetyTests(WrapperCase):
    def run_with_path(self, target: str):
        return self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(ZAPRET_BLOCKCHECK=target),
        )

    def test_refuses_missing_path(self):
        proc = self.run_with_path(str(self.bin_dir / "no-such-blockcheck.sh"))
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("does not resolve", proc.stdout)

    def test_refuses_directory(self):
        proc = self.run_with_path(str(self.bin_dir))
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)

    def test_refuses_wrong_basename(self):
        fake = self.install_mock("not-blockcheck.sh", MOCK_SUMMARY)
        proc = self.run_with_path(str(fake))
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("basename", proc.stdout)

    def test_refuses_world_writable(self):
        fake = self.install_mock("blockcheck.sh", MOCK_SUMMARY)
        fake.chmod(0o666)
        proc = self.run_with_path(str(fake))
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        self.assertIn("world-writable", proc.stdout)

    def test_accepts_original_default_path_and_forwards_it(self):
        self.assertTrue(ORIGINAL_BLOCKCHECK.is_file())
        proc = self.run_wrapper("--opt-in", "--self-test")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn("WOULD-RUN(in-netns-only)", proc.stdout)
        self.assertIn(str(ORIGINAL_BLOCKCHECK), proc.stdout)
        self.assertIn("ip netns exec dynam-zapret-lab", proc.stdout)

    def test_forwards_env_override_path(self):
        # A safe, non-executable-named copy still named blockcheck.sh.
        safe_dir = self.bin_dir / "zapret-copy"
        safe_dir.mkdir()
        target = self.install_mock(safe_dir / "blockcheck.sh", MOCK_SUMMARY)
        proc = self.run_with_path(str(target))
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertIn(str(target), proc.stdout)


class CleanupTrapTests(WrapperCase):
    def test_cleanup_after_successful_run(self):
        proc = self.run_wrapper("--opt-in", "--self-test")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertFalse(self.marker.exists(), "ownership marker must be removed")
        self.assertFalse(self.rawlog.exists(), "raw log must be removed")
        wlog = self.wlog.read_text()
        self.assertIn("cleanup: starting", wlog)
        self.assertIn("cleanup: done", wlog)

    def test_cleanup_after_mock_failure(self):
        mock = self.install_mock("fail.sh", MOCK_NO_SUMMARY)
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock)),
        )
        self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
        self.assertEqual(self.read_verdict()["verdict"], "FAIL")
        self.assertFalse(self.marker.exists())
        self.assertFalse(self.rawlog.exists())
        self.assertIn("cleanup: done", self.wlog.read_text())

    def test_cleanup_on_sigterm(self):
        started = self.bin_dir / "mock-started"
        mock = self.install_mock("sleep.sh", MOCK_SLEEP)
        env = self.base_env(
            DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock),
            DYNAM_ZAPRET_MOCK_STARTED=str(started),
        )
        proc = subprocess.Popen(
            ["bash", str(WRAPPER), "--opt-in", "--self-test"],
            env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        )
        try:
            deadline = time.time() + 10
            while not started.exists():
                self.assertLess(time.time(), deadline, "mock never started")
                self.assertIsNone(proc.poll(), "wrapper exited before mock start")
                time.sleep(0.05)
            self.assertTrue(self.marker.exists(), "marker must exist while running")
            proc.send_signal(signal.SIGTERM)
            out, _ = proc.communicate(timeout=15)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        self.assertEqual(proc.returncode, 2, out)
        self.assertIn("SIGTERM", out)
        self.assertFalse(self.marker.exists(), "trap must remove the marker")
        self.assertFalse(self.rawlog.exists(), "trap must remove the raw log")
        wlog = self.wlog.read_text()
        self.assertIn("cleanup: done", wlog)
        self.assertEqual(self.read_verdict()["verdict"], "NOT-RUN")


class SanitizationTests(WrapperCase):
    def test_no_secret_or_address_logging(self):
        mock = self.install_mock("dirty.sh", MOCK_DIRTY)
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(
                DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock),
                DYNAM_ZAPRET_REDACT="hunter2secret",
            ),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertFalse(self.rawlog.exists(), "raw log must be deleted by cleanup")
        combined = (
            self.slog.read_text()
            + self.wlog.read_text()
            + proc.stdout
            + proc.stderr
        )
        self.assertNotIn("198.51.100.7", combined)
        self.assertNotIn("2001:db8::dead:beef", combined)
        self.assertNotIn("hunter2secret", combined)
        slog = self.slog.read_text()
        self.assertIn("<redacted-ip>", slog)
        self.assertIn("<redacted-ip6>", slog)
        self.assertIn("<redacted-secret>", slog)


class VerdictParsingTests(WrapperCase):
    def test_pass_verdict_and_counts(self):
        mock = self.install_mock("ok.sh", MOCK_SUMMARY)
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock)),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        verdict = self.read_verdict()
        self.assertEqual(verdict["verdict"], "PASS")
        self.assertEqual(verdict["summary_seen"], "yes")
        self.assertEqual(verdict["available_strategies"], "1")
        self.assertEqual(verdict["unavailable_strategies"], "1")
        self.assertIn("NOT a replacement", verdict["scope"])

    def test_fail_verdict_without_summary(self):
        mock = self.install_mock("nosummary.sh", MOCK_NO_SUMMARY)
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock)),
        )
        self.assertEqual(proc.returncode, 1, proc.stderr + proc.stdout)
        verdict = self.read_verdict()
        self.assertEqual(verdict["verdict"], "FAIL")
        self.assertEqual(verdict["summary_seen"], "no")

    def test_verdict_file_uses_default_path_label(self):
        proc = self.run_wrapper("--opt-in", "--self-test")
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        verdict = self.read_verdict()
        self.assertEqual(verdict["blockcheck"], str(ORIGINAL_BLOCKCHECK))
        self.assertEqual(verdict["netns"], "dynam-zapret-lab")


class HermeticityTests(WrapperCase):
    def test_self_test_never_invokes_real_blockcheck_or_firewall(self):
        calls = self.bin_dir / "canary-calls.log"
        canary_touched = self.bin_dir / "canary-touched"
        # Fake privileged tools that log any invocation and fail loudly.
        for tool in ("ip", "iptables", "ip6tables", "nft", "ipfw", "pfctl", "unshare"):
            make_executable(
                self.bin_dir / tool,
                f'#!/bin/sh\necho "{tool} $*" >> "{calls}"\nexit 99\n',
            )
        canary = self.bin_dir / "zapret-copy" / "blockcheck.sh"
        canary.parent.mkdir()
        self.install_mock("zapret-copy/blockcheck.sh", CANARY_BLOCKCHECK)
        mock = self.install_mock("ok.sh", MOCK_SUMMARY)
        env = self.base_env(
            PATH=f"{self.bin_dir}:/usr/bin:/bin",
            ZAPRET_BLOCKCHECK=str(canary),
            DYNAM_ZAPRET_MOCK_BLOCKCHECK=str(mock),
            DYNAM_ZAPRET_CANARY=str(canary_touched),
        )
        proc = self.run_wrapper("--opt-in", "--self-test", env=env)
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertFalse(
            calls.exists(),
            f"self-test invoked privileged tools: {calls.read_text() if calls.exists() else ''}",
        )
        self.assertFalse(canary_touched.exists(), "self-test must never run blockcheck")

    def test_owned_state_requires_preexisting_marker(self):
        # No marker present: adopt must refuse.
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="owned"),
        )
        self.assertEqual(proc.returncode, 2, proc.stderr + proc.stdout)
        # With a valid marker present: adopt succeeds and keeps evidence flow.
        self.marker.write_text("inode=net:[4242]\ncreated_by=test\n")
        proc = self.run_wrapper(
            "--opt-in", "--self-test",
            env=self.base_env(DYNAM_ZAPRET_ST_NS_STATE="owned"),
        )
        self.assertEqual(proc.returncode, 0, proc.stderr + proc.stdout)
        self.assertFalse(self.marker.exists(), "cleanup must remove adopted marker")


if __name__ == "__main__":
    unittest.main()
