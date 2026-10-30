#!/usr/bin/env python3
"""
Unit tests for scripts/autodeploy/ssh_autodeploy.py.

All tests run offline: a scripted FakeTransport emulates the remote shell and
Docker daemon so the full deploy/status/destroy state machine is exercised
without any SSH server, Docker daemon or real credentials.
"""

import io
import json
import os
import socket
import sys
import tempfile
import threading
import unittest
from unittest import mock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "scripts", "autodeploy"))

import ssh_autodeploy as sad  # noqa: E402

PASSWORD = "s3cret-test-password"  # fake, used only to verify redaction

OS_RELEASE = 'PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"\nID=debian\nVERSION_ID="11"\n'
MEMINFO = "MemTotal:        2048000 kB\nMemFree:         1024000 kB\n"
IMAGE_ID = "sha256:" + "ab" * 32  # pinned fake image id
IMAGE_ID_BARE = "ab" * 32
OLD_CONFIG_SHA = sad.sha256_bytes(b"old config content")


def make_inspect(name, labels=None, health="healthy", running=True):
    state = {"Status": "running" if running else "exited", "Running": running}
    if health is not None:
        state["Health"] = {"Status": health}
    return {
        "Id": "cid-" + name,
        "Name": "/" + name,
        "Config": {"Labels": labels or {}},
        "State": state,
    }


class FakeTransport(sad.Transport):
    """Scripted remote shell + in-memory Docker daemon."""

    def __init__(self, containers=None, health_script=None, fail_commands=None):
        # containers: {name: inspect-dict}
        self.containers = dict(containers or {})
        self.health_script = list(health_script or [])  # statuses popped per inspect
        self.fail_commands = set(fail_commands or [])   # substrings forced to rc=1
        self.commands = []       # every exec() command, in order
        self.uploads = []        # (local_path, remote_path)
        self.lock_held = False
        self.closed = False
        self.secrets = [PASSWORD]

    # -- Transport interface -------------------------------------------------

    def exec(self, cmd, timeout=60):
        self.commands.append(cmd)
        if any(f in cmd for f in self.fail_commands):
            return sad.ExecResult(1, "", f"forced failure (password={PASSWORD})")
        return self._dispatch(cmd)

    def put_file(self, local_path, remote_path):
        self.uploads.append((local_path, remote_path))

    def close(self):
        self.closed = True

    # -- fake remote shell -----------------------------------------------------

    def _dispatch(self, cmd):
        if cmd == "cat /etc/os-release":
            return sad.ExecResult(0, OS_RELEASE, "")
        if cmd == "uname -m":
            return sad.ExecResult(0, "x86_64\n", "")
        if cmd == "id -u":
            return sad.ExecResult(0, "0\n", "")
        if cmd == "cat /proc/meminfo":
            return sad.ExecResult(0, MEMINFO, "")
        if cmd.startswith("docker version"):
            return sad.ExecResult(0, "24.0.7\n", "")
        if cmd.startswith("docker info"):
            return sad.ExecResult(0, "24.0.7\n", "")
        if cmd.startswith("df -Pm"):
            return sad.ExecResult(0, "Filesystem 1M-blocks Used Available Mounted on\n"
                                     "/dev/sda1 20000 5000 15000 /\n", "")
        if cmd == f"mkdir {sad.REMOTE_LOCK_DIR}":
            if self.lock_held:
                return sad.ExecResult(1, "", "File exists")
            self.lock_held = True
            return sad.ExecResult(0, "", "")
        if cmd == f"rmdir {sad.REMOTE_LOCK_DIR}":
            self.lock_held = False
            return sad.ExecResult(0, "", "")
        if cmd.startswith("mkdir -p"):
            return sad.ExecResult(0, "", "")
        if cmd.startswith("rm -f ") or cmd.startswith("rm -rf"):
            return sad.ExecResult(0, "", "")
        if cmd.startswith("docker"):
            return self._docker(cmd)
        raise AssertionError(f"unexpected remote command: {cmd}")

    # -- fake docker daemon ----------------------------------------------------

    def _docker(self, cmd):
        if cmd.startswith("docker image inspect"):
            return sad.ExecResult(0, IMAGE_ID + "\n", "")
        if cmd.startswith("docker inspect "):
            name = cmd.rsplit(" ", 1)[-1]
            insp = self.containers.get(name)
            if insp is None:
                return sad.ExecResult(1, "", f"Error: No such object: {name}")
            if self.health_script and name == sad.DEFAULT_CONTAINER_NAME:
                status = self.health_script.pop(0)
                insp["State"]["Health"]["Status"] = status
                insp["State"]["Running"] = status not in ("exited", "dead")
                if status in ("exited", "dead"):
                    insp["State"]["Status"] = status
            return sad.ExecResult(0, json.dumps([insp]), "")
        if cmd.startswith("docker create"):
            tokens = cmd.split()
            name = tokens[tokens.index("--name") + 1]
            labels = {}
            for i, tok in enumerate(tokens):
                if tok == "--label":
                    k, _, v = tokens[i + 1].partition("=")
                    labels[k] = v
            self.containers[name] = make_inspect(name, labels, health="starting")
            return sad.ExecResult(0, "newcid\n", "")
        if cmd.startswith("docker start "):
            name = cmd.rsplit(" ", 1)[-1]
            self.containers[name]["State"]["Running"] = True
            self.containers[name]["State"]["Status"] = "running"
            if not self.health_script and "Health" in self.containers[name]["State"]:
                self.containers[name]["State"]["Health"]["Status"] = "healthy"
            return sad.ExecResult(0, name + "\n", "")
        if cmd.startswith("docker stop "):
            name = cmd.rsplit(" ", 1)[-1]
            self.containers[name]["State"]["Running"] = False
            return sad.ExecResult(0, name + "\n", "")
        if cmd.startswith("docker rename "):
            _, _, old, new = cmd.split(" ", 3)
            self.containers[new] = self.containers.pop(old)
            return sad.ExecResult(0, "", "")
        if cmd.startswith("docker rm"):
            name = cmd.rsplit(" ", 1)[-1]
            self.containers.pop(name, None)
            return sad.ExecResult(0, name + "\n", "")
        raise AssertionError(f"unexpected docker command: {cmd}")


def base_cfg(command="deploy", **kw):
    params = dict(
        command=command,
        image_id=IMAGE_ID,
        health_cmd=["/usr/local/bin/ncp", "--help"],
        entrypoint="/usr/local/bin/ncp",
    )
    params.update(kw)
    return sad.DeployConfig(**params)


def instant_sleep(_sec):
    return None


def owned_labels(fingerprint="0" * 64, config_sha256=None):
    labels = {sad.OWNER_LABEL: sad.OWNER_VALUE, sad.LABEL_FINGERPRINT: fingerprint}
    if config_sha256:
        labels[sad.LABEL_CONFIG_SHA256] = config_sha256
    return labels


def write_temp(data):
    fh = tempfile.NamedTemporaryFile(delete=False)
    fh.write(data)
    fh.close()
    return fh.name


class TestPureHelpers(unittest.TestCase):
    def test_sha256_and_image_id_normalization(self):
        self.assertEqual(sad.sha256_bytes(b"abc"),
                         "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad")
        self.assertEqual(sad.normalize_image_id("SHA256:" + "AB" * 4), "ab" * 4)
        path = write_temp(b"abc")
        try:
            self.assertEqual(sad.sha256_file(path), sad.sha256_bytes(b"abc"))
        finally:
            os.unlink(path)

    def test_fingerprint_deterministic_and_sensitive(self):
        spec1 = sad.build_desired_spec(
            image="img", image_id=IMAGE_ID, config_sha256="aa",
            entrypoint="/usr/local/bin/ncp", command=["--x"],
            health_cmd=["/usr/local/bin/ncp", "--help"], cpus=1.0, memory_mb=256)
        spec2 = sad.build_desired_spec(
            image="img", image_id=IMAGE_ID, config_sha256="aa",
            entrypoint="/usr/local/bin/ncp", command=["--x"],
            health_cmd=["/usr/local/bin/ncp", "--help"], cpus=1.0, memory_mb=256)
        self.assertEqual(sad.compute_fingerprint(spec1), sad.compute_fingerprint(spec2))
        spec2["memory_mb"] = 512
        self.assertNotEqual(sad.compute_fingerprint(spec1), sad.compute_fingerprint(spec2))

    def test_parse_helpers(self):
        self.assertEqual(sad.parse_os_release(OS_RELEASE)["ID"], "debian")
        self.assertEqual(sad.parse_meminfo_total_mb(MEMINFO), 2000)
        self.assertTrue(sad.is_owned({sad.OWNER_LABEL: sad.OWNER_VALUE}))
        self.assertFalse(sad.is_owned({}))
        self.assertEqual(sad.inspect_state(make_inspect("x", health="starting")), "starting")
        self.assertEqual(sad.inspect_state(make_inspect("x", health=None, running=False)),
                         "exited")

    def test_sanitize_redacts_secrets(self):
        out = sad.sanitize_json({"msg": f"auth failed for {PASSWORD}"}, [PASSWORD])
        self.assertNotIn(PASSWORD, json.dumps(out))
        self.assertIn(sad.REDACTED, out["msg"])


class DeployTestBase(unittest.TestCase):
    def make_deployer(self, transport, cfg=None):
        return sad.Deployer(transport, cfg or base_cfg(), secrets=[PASSWORD],
                            sleep=instant_sleep)

    def joined(self, transport):
        return "\n".join(transport.commands)


class TestDeployFlow(DeployTestBase):
    def test_create_fresh_container_success(self):
        t = FakeTransport()
        d = self.make_deployer(t)
        result = d.deploy()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "create")
        self.assertEqual(result["status"], "healthy")
        self.assertFalse(t.lock_held, "remote lock must be released")
        joined = self.joined(t)
        self.assertIn("docker create", joined)
        self.assertNotIn("--publish", joined)
        self.assertNotIn(" -p ", joined)
        self.assertNotIn("iptables", joined)
        self.assertNotIn("nft", joined)
        insp = t.containers[sad.DEFAULT_CONTAINER_NAME]
        labels = insp["Config"]["Labels"]
        self.assertEqual(labels[sad.OWNER_LABEL], sad.OWNER_VALUE)
        self.assertEqual(labels[sad.LABEL_FINGERPRINT], result["fingerprint"])

    def test_create_uses_immutable_image_id_not_tag(self):
        # The container must be created from the verified sha256:<id>, never
        # from the mutable tag, to eliminate the verify-then-create TOCTOU.
        t = FakeTransport()
        result = self.make_deployer(t).deploy()
        self.assertTrue(result["ok"])
        create = [c for c in t.commands if c.startswith("docker create")][0]
        self.assertIn(f"sha256:{IMAGE_ID_BARE}", create)
        self.assertNotIn("dynam-dpi:client-debian11", create)

    def test_config_upload_content_addressed_and_exact_mount(self):
        cfg_path = write_temp(b"remote: example.invalid\n")
        try:
            cfg_sha = sad.sha256_file(cfg_path)
            t = FakeTransport()
            cfg = base_cfg(config_path=cfg_path)
            result = self.make_deployer(t, cfg).deploy()
            self.assertTrue(result["ok"])
            self.assertEqual(result["config_sha256"], cfg_sha)
            remote_cfg = f"{sad.REMOTE_STATE_DIR}/config/{cfg_sha}"
            self.assertEqual(t.uploads, [(cfg_path, remote_cfg)])
            create = [c for c in t.commands if c.startswith("docker create")][0]
            expected_mount = f"{remote_cfg}:/etc/dynam/{os.path.basename(cfg_path)}:ro"
            self.assertIn(expected_mount, create)
        finally:
            os.unlink(cfg_path)

    def test_idempotent_no_change(self):
        cfg = base_cfg()
        d0 = sad.Deployer(FakeTransport(), cfg, sleep=instant_sleep)
        fp = sad.compute_fingerprint(d0.desired_spec(None))
        t = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                           make_inspect(sad.DEFAULT_CONTAINER_NAME, owned_labels(fp))})
        result = self.make_deployer(t).deploy()
        self.assertTrue(result["ok"])
        self.assertEqual(result["action"], "no-change")
        joined = self.joined(t)
        self.assertNotIn("docker create", joined)
        self.assertNotIn("docker stop", joined)
        self.assertNotIn("docker rename", joined)

    def test_no_change_rejects_health_starting(self):
        # A container with the matching fingerprint but health=starting has
        # not proven itself: deploy must take the update path, not no-change.
        cfg = base_cfg()
        d0 = sad.Deployer(FakeTransport(), cfg, sleep=instant_sleep)
        fp = sad.compute_fingerprint(d0.desired_spec(None))
        t = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                           make_inspect(sad.DEFAULT_CONTAINER_NAME, owned_labels(fp),
                                        health="starting")})
        result = self.make_deployer(t).deploy()
        self.assertEqual(result["action"], "update")
        self.assertTrue(result["ok"])  # update itself succeeds in the fake

    def test_no_change_performs_no_config_upload(self):
        cfg_path = write_temp(b"remote: example.invalid\n")
        try:
            cfg_sha = sad.sha256_file(cfg_path)
            cfg = base_cfg(config_path=cfg_path)
            d0 = sad.Deployer(FakeTransport(), cfg, sleep=instant_sleep)
            fp = sad.compute_fingerprint(d0.desired_spec(cfg_sha))
            t = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                               make_inspect(sad.DEFAULT_CONTAINER_NAME,
                                            owned_labels(fp, cfg_sha))})
            result = self.make_deployer(t, cfg).deploy()
            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "no-change")
            self.assertEqual(t.uploads, [], "no-change must not upload config")
        finally:
            os.unlink(cfg_path)

    def test_foreign_container_refusal(self):
        # Existing container without owner label -> hard refusal, untouched.
        t = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                           make_inspect(sad.DEFAULT_CONTAINER_NAME, labels={})})
        d = self.make_deployer(t)
        with self.assertRaises(sad.ForeignContainerError):
            d.deploy()
        self.assertIn(sad.DEFAULT_CONTAINER_NAME, t.containers)
        joined = self.joined(t)
        self.assertNotIn("docker stop", joined)
        self.assertNotIn("docker rename", joined)
        self.assertFalse(t.lock_held)

    def test_foreign_backup_rejected_before_stopping_primary(self):
        # A foreign backup must be rejected BEFORE the primary is stopped:
        # the refusal leaves the primary running.
        main = sad.DEFAULT_CONTAINER_NAME
        backup = main + ".backup"
        t = FakeTransport({
            main: make_inspect(main, owned_labels()),       # stale fingerprint
            backup: make_inspect(backup, labels={}),        # foreign backup
        })
        d = self.make_deployer(t)
        with self.assertRaises(sad.ForeignContainerError):
            d.deploy()
        joined = self.joined(t)
        self.assertNotIn("docker stop", joined, "primary must not be stopped")
        self.assertNotIn("docker rename", joined)
        self.assertTrue(t.containers[main]["State"]["Running"], "primary left running")
        self.assertIn(backup, t.containers, "foreign backup untouched")

    def test_update_failure_reports_not_ok_with_rollback_ok(self):
        # Failed desired update: ok is False (nonzero) even though the
        # rollback succeeds; rollback health is reported separately.
        main = sad.DEFAULT_CONTAINER_NAME
        old = make_inspect(main, owned_labels())
        # preflight inspect + plan inspect consume 2; the 3rd (new container)
        # reports exited and fails the health wait immediately.
        t = FakeTransport({main: old},
                          health_script=["starting", "starting", "exited"])
        d = self.make_deployer(t)
        result = d.deploy()
        self.assertFalse(result["ok"], "failed desired update must never report ok")
        self.assertTrue(result.get("rollback"))
        self.assertTrue(result["rollback_ok"], "rollback itself succeeded")
        self.assertEqual(result["status"], "rolled-back")
        joined = self.joined(t)
        self.assertIn(f"docker rename {main} {main}.backup", joined)
        self.assertIn(f"docker rename {main}.backup {main}", joined)
        # The restored original container is present and running again.
        self.assertIn(main, t.containers)
        self.assertTrue(t.containers[main]["State"]["Running"])
        self.assertNotIn(main + ".backup", t.containers)
        self.assertFalse(t.lock_held)

    def test_rollback_start_failure_reported(self):
        # docker start fails both for the new container and for the restored
        # backup: rollback must be verified and reported as failed.
        main = sad.DEFAULT_CONTAINER_NAME
        t = FakeTransport({main: make_inspect(main, owned_labels())},
                          fail_commands=["docker start"])
        result = self.make_deployer(t).deploy()
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("rollback"))
        self.assertFalse(result["rollback_ok"], "rollback docker start failure detected")
        self.assertEqual(result["status"], "rollback-failed")

    def test_create_failure_has_nothing_to_roll_back(self):
        t = FakeTransport(fail_commands=["docker create"])
        result = self.make_deployer(t).deploy()
        self.assertFalse(result["ok"])
        self.assertTrue(result.get("rollback"))
        self.assertIsNone(result["rollback_ok"])
        self.assertEqual(result["status"], "failed")
        self.assertNotIn(sad.DEFAULT_CONTAINER_NAME, t.containers)

    def test_config_update_rollback_preserves_old_config(self):
        # Content-addressed configs: the failed update's config never
        # overwrites the config still mounted by the old backup container.
        cfg_path = write_temp(b"new config content\n")
        new_sha = sad.sha256_file(cfg_path)
        self.assertNotEqual(new_sha, OLD_CONFIG_SHA)
        try:
            main = sad.DEFAULT_CONTAINER_NAME
            old = make_inspect(main, owned_labels(config_sha256=OLD_CONFIG_SHA))
            t = FakeTransport({main: old},
                              health_script=["starting", "starting", "exited"])
            result = self.make_deployer(t, base_cfg(config_path=cfg_path)).deploy()
            self.assertFalse(result["ok"])
            self.assertTrue(result["rollback_ok"])
            old_path = f"{sad.REMOTE_STATE_DIR}/config/{OLD_CONFIG_SHA}"
            new_path = f"{sad.REMOTE_STATE_DIR}/config/{new_sha}"
            # Only the new, content-addressed path was uploaded...
            self.assertEqual(t.uploads, [(cfg_path, new_path)])
            # ...the old config file was never touched...
            self.assertNotIn(f"rm -f {old_path}", t.commands)
            # ...and the orphaned new config version was cleaned up.
            self.assertIn(f"rm -f {new_path}", t.commands)
        finally:
            os.unlink(cfg_path)

    def test_successful_update_removes_backup_and_old_config(self):
        cfg_path = write_temp(b"new config content\n")
        new_sha = sad.sha256_file(cfg_path)
        try:
            main = sad.DEFAULT_CONTAINER_NAME
            old = make_inspect(main, owned_labels(config_sha256=OLD_CONFIG_SHA))
            t = FakeTransport({main: old})
            result = self.make_deployer(t, base_cfg(config_path=cfg_path)).deploy()
            self.assertTrue(result["ok"])
            self.assertEqual(result["action"], "update")
            self.assertTrue(result.get("backup_removed"))
            self.assertTrue(result.get("old_config_removed"))
            self.assertNotIn(main + ".backup", t.containers)
            old_path = f"{sad.REMOTE_STATE_DIR}/config/{OLD_CONFIG_SHA}"
            new_path = f"{sad.REMOTE_STATE_DIR}/config/{new_sha}"
            self.assertIn(f"rm -f {old_path}", t.commands)
            self.assertNotIn(f"rm -f {new_path}", t.commands)
        finally:
            os.unlink(cfg_path)

    def test_image_id_mismatch_aborts(self):
        t = FakeTransport()
        d = self.make_deployer(t, base_cfg(image_id="sha256:" + "ff" * 32))
        with self.assertRaises(sad.AutoDeployError):
            d.deploy()
        self.assertNotIn("docker create", self.joined(t))

    def test_docker_inspect_error_raises_instead_of_absent(self):
        # Only "No such object" means absent; other docker errors raise.
        t = FakeTransport(fail_commands=["docker inspect"])
        d = self.make_deployer(t)
        with self.assertRaises(sad.AutoDeployError) as ctx:
            d._docker_inspect(sad.DEFAULT_CONTAINER_NAME)
        self.assertNotIn(PASSWORD, str(ctx.exception))
        # "No such object" still maps to absent.
        t2 = FakeTransport()
        d2 = self.make_deployer(t2)
        self.assertIsNone(d2._docker_inspect(sad.DEFAULT_CONTAINER_NAME))

    def test_remote_lock_refusal(self):
        t = FakeTransport()
        t.lock_held = True  # someone else holds it
        d = self.make_deployer(t)
        with self.assertRaises(sad.LockHeldError):
            d.deploy()
        self.assertNotIn("docker create", self.joined(t))

    def test_no_secret_in_output_or_errors(self):
        # Force a remote failure whose stderr embeds the password; the error
        # surfaced by the deployer must be redacted.
        t = FakeTransport(fail_commands=["cat /etc/os-release"])
        d = self.make_deployer(t)
        with self.assertRaises(sad.AutoDeployError) as ctx:
            d.deploy()
        self.assertNotIn(PASSWORD, str(ctx.exception))
        self.assertIn(sad.REDACTED, str(ctx.exception))


class TestStatusDestroy(DeployTestBase):
    def test_status_absent_and_present(self):
        t = FakeTransport()
        result = self.make_deployer(t, base_cfg(command="status")).status()
        self.assertEqual(result["status"], "absent")

        t2 = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                            make_inspect(sad.DEFAULT_CONTAINER_NAME,
                                         owned_labels("x"))})
        result2 = self.make_deployer(t2, base_cfg(command="status")).status()
        self.assertTrue(result2["present"])
        self.assertTrue(result2["owned"])
        self.assertEqual(result2["fingerprint"], "x")

    def test_destroy_owned(self):
        main = sad.DEFAULT_CONTAINER_NAME
        t = FakeTransport({main: make_inspect(main, owned_labels())})
        result = self.make_deployer(t, base_cfg(command="destroy")).destroy()
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "destroyed")
        self.assertNotIn(main, t.containers)
        self.assertIn(f"rm -rf {sad.REMOTE_STATE_DIR}", t.commands)
        self.assertFalse(t.lock_held)

    def test_destroy_main_absent_still_cleans_backup_and_state(self):
        # Main container absent: an owned backup and the managed remote_dir
        # (including content-addressed config versions) are still cleaned.
        backup = sad.DEFAULT_CONTAINER_NAME + ".backup"
        t = FakeTransport({backup: make_inspect(backup, owned_labels())})
        result = self.make_deployer(t, base_cfg(command="destroy")).destroy()
        self.assertTrue(result["ok"])
        self.assertEqual(result["status"], "absent")
        self.assertIn("backup", result["removed"])
        self.assertNotIn(backup, t.containers)
        self.assertIn(f"rm -rf {sad.REMOTE_STATE_DIR}", t.commands)
        self.assertFalse(t.lock_held)

    def test_destroy_foreign_refused(self):
        t = FakeTransport({sad.DEFAULT_CONTAINER_NAME:
                           make_inspect(sad.DEFAULT_CONTAINER_NAME, labels={})})
        with self.assertRaises(sad.ForeignContainerError):
            self.make_deployer(t, base_cfg(command="destroy")).destroy()
        self.assertIn(sad.DEFAULT_CONTAINER_NAME, t.containers)


class TestParamikoHostKeyPinning(unittest.TestCase):
    """In-memory SSH handshake: no listener, network or real credentials."""

    def run_handshake(self, correct_pin):
        import paramiko

        host_key = paramiko.RSAKey.generate(2048)
        client_sock, server_sock = socket.socketpair()
        auth_calls = []
        server_errors = []

        class Server(paramiko.ServerInterface):
            def get_allowed_auths(self, username):
                return "password"

            def check_auth_password(self, username, password):
                auth_calls.append((username, password))
                return paramiko.AUTH_SUCCESSFUL

            def check_channel_request(self, kind, chanid):
                return paramiko.OPEN_SUCCEEDED

        server_transport = paramiko.Transport(server_sock)
        server_transport.add_server_key(host_key)

        def serve():
            try:
                server_transport.start_server(server=Server())
            except Exception as exc:  # pragma: no cover - diagnostic only
                server_errors.append(str(exc))

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        pin = sad.host_key_sha256_hex(host_key.asbytes())
        presented_pin = pin if correct_pin else "00" * 32
        fake_sftp = mock.Mock()
        old_password = os.environ.get("DYNAM_SSH_PASSWORD")
        os.environ["DYNAM_SSH_PASSWORD"] = PASSWORD
        transport = None
        try:
            with mock.patch("socket.create_connection", return_value=client_sock), \
                 mock.patch.object(paramiko.SFTPClient, "from_transport",
                                   return_value=fake_sftp):
                if correct_pin:
                    transport = sad.ParamikoTransport(
                        "loopback.invalid", 22, "lab", presented_pin)
                else:
                    with self.assertRaises(sad.AutoDeployError):
                        sad.ParamikoTransport(
                            "loopback.invalid", 22, "lab", presented_pin)
        finally:
            if transport is not None:
                transport.close()
            server_transport.close()
            client_sock.close()
            thread.join(timeout=2)
            if old_password is None:
                os.environ.pop("DYNAM_SSH_PASSWORD", None)
            else:
                os.environ["DYNAM_SSH_PASSWORD"] = old_password
        self.assertFalse(server_errors)
        return auth_calls

    def test_correct_pin_allows_password_auth(self):
        self.assertEqual(self.run_handshake(True), [("lab", PASSWORD)])

    def test_wrong_pin_refuses_before_password_auth(self):
        self.assertEqual(self.run_handshake(False), [])


class TestCLI(unittest.TestCase):
    def test_parser_has_no_password_option(self):
        parser = sad.build_arg_parser()
        opts = {a for action in parser._actions for a in action.option_strings}
        self.assertNotIn("--password", opts)
        self.assertIn("--host-key-sha256", opts)

    def test_help_documents_stale_lock_recovery(self):
        parser = sad.build_arg_parser()
        help_text = parser.format_help()
        self.assertIn("rmdir /run/dynam-autodeploy.lock", help_text)

    def test_config_from_args(self):
        args = sad.build_arg_parser().parse_args(
            ["deploy", "--host", "192.0.2.10", "--host-key-sha256", "ab" * 32,
             "--image-id", IMAGE_ID, "--cpus", "1.5", "--memory-mb", "256",
             "--cmd-args", "--profile x", "--health-cmd", "/usr/local/bin/ncp --help"])
        cfg = sad.config_from_args(args)
        self.assertEqual(cfg.cpus, 1.5)
        self.assertEqual(cfg.memory_mb, 256)
        self.assertEqual(cfg.entrypoint, "/usr/local/bin/ncp")
        self.assertEqual(cfg.health_cmd, ["/usr/local/bin/ncp", "--help"])

    def run_main(self, argv):
        buf = io.StringIO()
        old = sys.stdout
        sys.stdout = buf
        try:
            rc = sad.main(argv)
        finally:
            sys.stdout = old
        return rc, json.loads(buf.getvalue())

    def test_main_without_password_env_fails_safely(self):
        os.environ.pop("DYNAM_SSH_PASSWORD", None)
        rc, out = self.run_main(["status", "--host", "192.0.2.10",
                                 "--host-key-sha256", "ab" * 32])
        self.assertEqual(rc, 1)
        self.assertFalse(out["ok"])
        self.assertIn("DYNAM_SSH_PASSWORD", out["error"])

    def test_main_redacts_password_from_transport_construction_errors(self):
        # Secrets are seeded before Paramiko construction, so even an error
        # raised while building the transport is redacted in the JSON output.
        os.environ["DYNAM_SSH_PASSWORD"] = PASSWORD
        original = sad.ParamikoTransport

        def boom(*_a, **_k):
            raise RuntimeError(f"handshake failed, password={PASSWORD}")

        sad.ParamikoTransport = boom
        try:
            rc, out = self.run_main(["status", "--host", "192.0.2.10",
                                     "--host-key-sha256", "ab" * 32])
        finally:
            sad.ParamikoTransport = original
            os.environ.pop("DYNAM_SSH_PASSWORD", None)
        self.assertEqual(rc, 1)
        self.assertFalse(out["ok"])
        self.assertNotIn(PASSWORD, json.dumps(out))
        self.assertIn(sad.REDACTED, out["error"])

    def test_main_failed_update_exits_nonzero(self):
        # End-to-end through main(): a failed update whose rollback succeeds
        # still exits 1 and reports ok=false with rollback_ok=true.
        main = sad.DEFAULT_CONTAINER_NAME
        fake = FakeTransport({main: make_inspect(main, owned_labels())},
                             health_script=["starting", "starting", "exited"])
        os.environ["DYNAM_SSH_PASSWORD"] = PASSWORD
        original = sad.ParamikoTransport
        sad.ParamikoTransport = lambda *a, **k: fake
        try:
            rc, out = self.run_main(["deploy", "--host", "192.0.2.10",
                                     "--host-key-sha256", "ab" * 32,
                                     "--image-id", IMAGE_ID])
        finally:
            sad.ParamikoTransport = original
            os.environ.pop("DYNAM_SSH_PASSWORD", None)
        self.assertEqual(rc, 1)
        self.assertFalse(out["ok"])
        self.assertTrue(out["rollback"])
        self.assertTrue(out["rollback_ok"])
        self.assertEqual(out["status"], "rolled-back")


if __name__ == "__main__":
    unittest.main()
