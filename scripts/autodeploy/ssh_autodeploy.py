#!/usr/bin/env python3
"""
Safe SSH AutoDeploy CLI for the Dynam project (standalone, lab-oriented).

This tool deploys a single dedicated Docker container on a remote Debian/Ubuntu
host over SSH/SFTP (paramiko). It is deliberately standalone: it does NOT read,
modify or depend on deploy/install.sh or any docker-compose files.

Safety properties
-----------------
* SSH password is read ONLY from the ``DYNAM_SSH_PASSWORD`` environment
  variable. It is never accepted via argv and never written to logs/stdout.
* Mandatory SHA256 host-key pinning (``--host-key-sha256``). The fingerprint
  is verified before password authentication is attempted.
* Remote preflight: Debian/Ubuntu, x86_64, root, Docker present and working,
  disk/memory thresholds, conflicting container name ownership.
* Every container we manage carries explicit owner labels
  (``dynam.autodeploy.*``). Containers without the owner label are treated as
  FOREIGN and are never stopped, renamed or removed.
* Pinned image ID verification: the local/remote image ID must match
  ``--image-id`` exactly before any container is created, and the new
  container is created from the immutable ``sha256:<id>`` reference (not the
  mutable tag) so a retagged image cannot slip in after verification.
* Deploy supports config file upload (SFTP, read-only mount), CPU/RAM limits,
  a Docker healthcheck with a bounded health wait, idempotent no-change when
  the desired fingerprint already matches (a merely "starting" container is
  NOT accepted as no-change), a safe update path (stop/rename old container
  to a backup, start the new one), automatic rollback on health failure, a
  remote lock, and cleanup of the backup.
* Config files are uploaded to content-addressed remote paths
  (``<remote_dir>/config/<sha256>``) and the exact desired file is bind
  mounted. A failed config update therefore never overwrites the config that
  the old (backup) container still mounts, so rollback restores the old
  config as well as the old container.
* A failed desired update ALWAYS reports ``ok: false`` (nonzero exit) even
  when the rollback succeeds; rollback success is reported separately via
  ``rollback_ok``.
* No ports are published by default and no firewall changes are made.
* All machine-readable output is a single sanitized JSON document on stdout;
  secrets are redacted.

Remote lock stale recovery
--------------------------
The remote lock (``/run/dynam-autodeploy.lock``) is a mkdir-based mutex that
is released on every normal exit path. If a deploy process is killed hard
(e.g. local power loss) the lock directory can remain behind: verify that no
autodeploy operation is actually running on the host, then remove it manually
with ``rmdir /run/dynam-autodeploy.lock`` and re-run the command.

The image entrypoint and health command are configurable so the flow can be
exercised against the existing ``dynam-dpi:client-debian11`` image whose
``ncp`` binary lives at ``/usr/local/bin/ncp``.

Commands: deploy / status / destroy.

Unit tests drive the same logic through a fake transport (see
tests/test_ssh_autodeploy.py).
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import sys
import time
from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Sequence, Tuple

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

OWNER_LABEL = "dynam.autodeploy.owner"
OWNER_VALUE = "dynam-autodeploy"
LABEL_FINGERPRINT = "dynam.autodeploy.fingerprint"
LABEL_IMAGE_ID = "dynam.autodeploy.image-id"
LABEL_CONFIG_SHA256 = "dynam.autodeploy.config-sha256"
LABEL_CREATED = "dynam.autodeploy.created"

DEFAULT_CONTAINER_NAME = "dynam-autodeploy"
REMOTE_STATE_DIR = "/etc/dynam-autodeploy"
REMOTE_LOCK_DIR = "/run/dynam-autodeploy.lock"

MIN_DISK_MB = 512
MIN_MEMORY_MB = 256
HEALTH_WAIT_DEFAULT_SEC = 60
HEALTH_POLL_INTERVAL_SEC = 2

REDACTED = "***REDACTED***"


class AutoDeployError(Exception):
    """Fatal, user-facing deployment error (reported in JSON output)."""


class ForeignContainerError(AutoDeployError):
    """Raised when the target container exists but is not owned by us."""


class LockHeldError(AutoDeployError):
    """Raised when the remote deploy lock is already held."""


# ---------------------------------------------------------------------------
# Pure helpers (unit-testable without any transport)
# ---------------------------------------------------------------------------

def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def normalize_image_id(image_id: str) -> str:
    """Normalize an image ID to bare lowercase hex (strip sha256: prefix)."""
    image_id = image_id.strip().lower()
    if image_id.startswith("sha256:"):
        image_id = image_id[len("sha256:"):]
    return image_id


def compute_fingerprint(spec: Dict[str, object]) -> str:
    """Deterministic SHA256 fingerprint of the desired-state spec.

    The spec is serialized as canonical JSON (sorted keys, tight separators)
    so identical desired states always hash identically.
    """
    blob = json.dumps(spec, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return sha256_bytes(blob)


def build_desired_spec(
    *,
    image: str,
    image_id: str,
    config_sha256: Optional[str],
    entrypoint: str,
    command: Sequence[str],
    health_cmd: Sequence[str],
    cpus: Optional[float],
    memory_mb: Optional[int],
) -> Dict[str, object]:
    """Build the desired-state dictionary that is fingerprinted and labeled."""
    return {
        "image": image,
        "image_id": normalize_image_id(image_id),
        "config_sha256": config_sha256,
        "entrypoint": entrypoint,
        "command": list(command),
        "health_cmd": list(health_cmd),
        "cpus": cpus,
        "memory_mb": memory_mb,
    }


def is_owned(labels: Dict[str, str]) -> bool:
    """True only if the container carries our explicit owner label."""
    return labels.get(OWNER_LABEL) == OWNER_VALUE


def parse_os_release(text: str) -> Dict[str, str]:
    out: Dict[str, str] = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        out[key.strip()] = value.strip().strip('"')
    return out


def parse_meminfo_total_mb(text: str) -> int:
    for line in text.splitlines():
        if line.startswith("MemTotal:"):
            parts = line.split()
            return int(parts[1]) // 1024  # kB -> MB
    return 0


def sanitize_text(text: str, secrets: Sequence[str] = ()) -> str:
    """Redact secrets and control characters from arbitrary text."""
    if text is None:
        return ""
    for secret in secrets:
        if secret:
            text = text.replace(secret, REDACTED)
    # Strip non-printable characters (keep \n and \t).
    return "".join(c for c in text if c in "\n\t" or c.isprintable())


def sanitize_json(obj: object, secrets: Sequence[str] = ()) -> object:
    """Recursively sanitize a JSON-serializable structure."""
    if isinstance(obj, str):
        return sanitize_text(obj, secrets)
    if isinstance(obj, dict):
        return {sanitize_text(str(k), secrets): sanitize_json(v, secrets) for k, v in obj.items()}
    if isinstance(obj, (list, tuple)):
        return [sanitize_json(v, secrets) for v in obj]
    return obj


def host_key_sha256_hex(key_bytes: bytes) -> str:
    """SHA256 fingerprint (hex) of a raw SSH host key blob."""
    return hashlib.sha256(key_bytes).hexdigest()


# ---------------------------------------------------------------------------
# Transport abstraction
# ---------------------------------------------------------------------------

@dataclass
class ExecResult:
    code: int
    out: str
    err: str


class Transport:
    """Minimal remote-execution interface used by the deploy logic.

    The production implementation is :class:`ParamikoTransport`; unit tests
    substitute a scripted fake.
    """

    def exec(self, cmd: str, timeout: int = 60) -> ExecResult:  # pragma: no cover
        raise NotImplementedError

    def put_file(self, local_path: str, remote_path: str) -> None:  # pragma: no cover
        raise NotImplementedError

    def close(self) -> None:  # pragma: no cover
        pass


class ParamikoTransport(Transport):
    """SSH/SFTP transport with mandatory SHA256 host-key pinning.

    The host key fingerprint is verified *before* password authentication, so
    credentials are never sent to an unpinned host. The password comes only
    from the DYNAM_SSH_PASSWORD environment variable.
    """

    def __init__(self, host: str, port: int, user: str, host_key_sha256: str,
                 timeout: int = 30) -> None:
        import paramiko  # imported lazily so pure-logic tests need no paramiko

        password = os.environ.get("DYNAM_SSH_PASSWORD")
        if not password:
            raise AutoDeployError(
                "DYNAM_SSH_PASSWORD environment variable is not set; "
                "password is never accepted via command line."
            )
        self._secrets = [password]
        expected = host_key_sha256.strip().lower().replace(":", "")
        sock = __import__("socket").create_connection((host, port), timeout=timeout)
        self._transport = paramiko.Transport(sock)
        try:
            self._transport.start_client(timeout=timeout)
        except Exception:
            # Handshake/banner failures must not leak the open socket.
            self._transport.close()
            raise
        remote_key = self._transport.get_remote_server_key()
        actual = host_key_sha256_hex(remote_key.asbytes())
        if actual.lower() != expected:
            self._transport.close()
            raise AutoDeployError(
                "host key SHA256 mismatch: expected pinned key, got a different key; "
                "refusing to authenticate"
            )
        self._transport.auth_password(username=user, password=password)
        if not self._transport.is_authenticated():
            self._transport.close()
            raise AutoDeployError("SSH authentication failed")
        self._sftp = paramiko.SFTPClient.from_transport(self._transport)

    @property
    def secrets(self) -> List[str]:
        return self._secrets

    def exec(self, cmd: str, timeout: int = 60) -> ExecResult:
        # Drain stdout and stderr concurrently: a naive stdout.read() followed
        # by stderr.read() can deadlock when the remote process fills the
        # stderr channel window while we are blocked reading stdout.
        import select

        chan = self._transport.open_session(timeout=timeout)
        chan.settimeout(float(timeout))
        out_chunks: List[bytes] = []
        err_chunks: List[bytes] = []
        try:
            chan.exec_command(cmd)
            while True:
                while chan.recv_ready():
                    out_chunks.append(chan.recv(65536))
                while chan.recv_stderr_ready():
                    err_chunks.append(chan.recv_stderr(65536))
                if chan.exit_status_ready():
                    # Final drain of anything buffered after exit.
                    while chan.recv_ready():
                        out_chunks.append(chan.recv(65536))
                    while chan.recv_stderr_ready():
                        err_chunks.append(chan.recv_stderr(65536))
                    break
                select.select([chan], [], [], 0.1)
            code = chan.recv_exit_status()
        finally:
            chan.close()
        return ExecResult(
            code=code,
            out=b"".join(out_chunks).decode("utf-8", "replace"),
            err=b"".join(err_chunks).decode("utf-8", "replace"),
        )

    def put_file(self, local_path: str, remote_path: str) -> None:
        self._sftp.put(local_path, remote_path)

    def close(self) -> None:
        try:
            self._sftp.close()
        finally:
            self._transport.close()


# ---------------------------------------------------------------------------
# Deploy engine
# ---------------------------------------------------------------------------

@dataclass
class DeployConfig:
    """Validated deploy parameters (already stripped of secrets)."""

    command: str  # deploy | status | destroy
    container_name: str = DEFAULT_CONTAINER_NAME
    image: str = "dynam-dpi:client-debian11"
    image_id: str = ""
    config_path: Optional[str] = None
    entrypoint: str = "/usr/local/bin/ncp"
    cmd_args: List[str] = field(default_factory=list)
    health_cmd: List[str] = field(default_factory=lambda: ["/usr/local/bin/ncp", "--help"])
    cpus: Optional[float] = None
    memory_mb: Optional[int] = None
    health_wait_sec: int = HEALTH_WAIT_DEFAULT_SEC
    min_disk_mb: int = MIN_DISK_MB
    min_memory_mb: int = MIN_MEMORY_MB
    remote_dir: str = REMOTE_STATE_DIR

    @property
    def backup_name(self) -> str:
        return f"{self.container_name}.backup"


class Deployer:
    """State machine for deploy/status/destroy against a Transport."""

    def __init__(self, transport: Transport, cfg: DeployConfig,
                 secrets: Sequence[str] = (),
                 now: Callable[[], float] = time.time,
                 sleep: Callable[[float], None] = time.sleep) -> None:
        self.t = transport
        self.cfg = cfg
        self.secrets = list(secrets)
        self.now = now
        self.sleep = sleep
        self._lock_acquired = False

    # -- low-level helpers ---------------------------------------------------

    def _run(self, cmd: str, timeout: int = 60, check: bool = True) -> ExecResult:
        res = self.t.exec(cmd, timeout=timeout)
        if check and res.code != 0:
            raise AutoDeployError(
                f"remote command failed ({res.code}): {sanitize_text(cmd, self.secrets)}: "
                f"{sanitize_text(res.err.strip() or res.out.strip(), self.secrets)}"
            )
        return res

    def _docker_inspect(self, name: str) -> Optional[Dict[str, object]]:
        """Return the inspect document, or None ONLY if the object is absent.

        Any other docker failure (daemon down, permission error, ...) raises
        so it is never mistaken for "container absent".
        """
        res = self.t.exec(f"docker inspect {shlex.quote(name)}", timeout=30)
        if res.code != 0:
            detail = (res.err.strip() or res.out.strip())
            if "No such object" in detail:
                return None
            raise AutoDeployError(
                f"docker inspect failed ({res.code}) for '{name}': "
                f"{sanitize_text(detail, self.secrets)}"
            )
        try:
            data = json.loads(res.out)
        except json.JSONDecodeError as exc:
            raise AutoDeployError(f"cannot parse docker inspect output: {exc}")
        if not data:
            return None
        return data[0]

    def _labels_of(self, inspect: Dict[str, object]) -> Dict[str, str]:
        cfg = inspect.get("Config") or {}
        return dict(cfg.get("Labels") or {})

    def _require_owned(self, inspect: Optional[Dict[str, object]], name: str) -> None:
        """Foreign-container refusal: never touch containers we do not own."""
        if inspect is not None and not is_owned(self._labels_of(inspect)):
            raise ForeignContainerError(
                f"container '{name}' exists but is not owned by {OWNER_VALUE}; refusing to touch it"
            )

    # -- remote lock ---------------------------------------------------------

    def acquire_lock(self) -> None:
        res = self.t.exec(f"mkdir {shlex.quote(REMOTE_LOCK_DIR)}", timeout=15)
        if res.code != 0:
            raise LockHeldError(
                f"another autodeploy operation holds the remote lock ({REMOTE_LOCK_DIR}); "
                "if a previous run was killed and the lock is stale, verify no autodeploy "
                f"is running, then remove it with: rmdir {REMOTE_LOCK_DIR}"
            )
        self._lock_acquired = True

    def release_lock(self) -> None:
        if self._lock_acquired:
            self.t.exec(f"rmdir {shlex.quote(REMOTE_LOCK_DIR)}", timeout=15)
            self._lock_acquired = False

    # -- preflight -----------------------------------------------------------

    def preflight(self) -> List[Dict[str, object]]:
        """Run all remote preflight checks; returns structured results.

        Raises AutoDeployError on the first hard failure.
        """
        checks: List[Dict[str, object]] = []

        def record(name: str, ok: bool, detail: str) -> None:
            checks.append({"name": name, "ok": ok, "detail": sanitize_text(detail, self.secrets)})
            if not ok:
                raise AutoDeployError(f"preflight check failed: {name}: {detail}")

        os_release = parse_os_release(self._run("cat /etc/os-release").out)
        distro = os_release.get("ID", "").lower()
        record("os", distro in ("debian", "ubuntu"), f"ID={distro or 'unknown'}")

        arch = self._run("uname -m").out.strip()
        record("arch", arch == "x86_64", arch)

        uid = self._run("id -u").out.strip()
        record("root", uid == "0", f"uid={uid}")

        docker_ver = self.t.exec("docker version --format '{{.Server.Version}}'", timeout=30)
        record("docker-present", docker_ver.code == 0 and bool(docker_ver.out.strip()),
               docker_ver.out.strip() or docker_ver.err.strip())

        docker_info = self.t.exec("docker info --format '{{.ServerVersion}}'", timeout=30)
        record("docker-working", docker_info.code == 0 and bool(docker_info.out.strip()),
               docker_info.out.strip() or docker_info.err.strip())

        df = self._run(f"df -Pm {shlex.quote(self.cfg.remote_dir)} 2>/dev/null || df -Pm /").out
        avail_mb = 0
        for line in df.splitlines()[1:]:
            parts = line.split()
            if len(parts) >= 4 and parts[3].isdigit():
                avail_mb = int(parts[3])
        record("disk", avail_mb >= self.cfg.min_disk_mb, f"avail={avail_mb}MB")

        mem_mb = parse_meminfo_total_mb(self._run("cat /proc/meminfo").out)
        record("memory", mem_mb >= self.cfg.min_memory_mb, f"total={mem_mb}MB")

        existing = self._docker_inspect(self.cfg.container_name)
        if existing is not None:
            if not is_owned(self._labels_of(existing)):
                checks.append({"name": "name-ownership", "ok": False,
                               "detail": "foreign-container"})
                raise ForeignContainerError(
                    f"container '{self.cfg.container_name}' exists but is not owned by "
                    f"{OWNER_VALUE}; refusing to touch it"
                )
            record("name-ownership", True, "owned-by-autodeploy")
        else:
            record("name-ownership", True, "no-conflict")
        return checks

    # -- image pinning --------------------------------------------------------

    def verify_image_id(self) -> str:
        """Verify the remote image ID matches the pinned --image-id exactly."""
        res = self._run(
            f"docker image inspect --format '{{{{.Id}}}}' {shlex.quote(self.cfg.image)}",
            timeout=30,
        )
        actual = normalize_image_id(res.out.strip())
        expected = normalize_image_id(self.cfg.image_id)
        if not expected:
            raise AutoDeployError("--image-id is required (pinned image verification)")
        if actual != expected:
            raise AutoDeployError(
                f"image ID mismatch for {self.cfg.image}: pinned {expected[:12]}..., "
                f"remote has {actual[:12] or 'MISSING'}..."
            )
        return actual

    # -- desired state / idempotency -----------------------------------------

    def desired_spec(self, config_sha256: Optional[str]) -> Dict[str, object]:
        return build_desired_spec(
            image=self.cfg.image,
            image_id=self.cfg.image_id,
            config_sha256=config_sha256,
            entrypoint=self.cfg.entrypoint,
            command=self.cfg.cmd_args,
            health_cmd=self.cfg.health_cmd,
            cpus=self.cfg.cpus,
            memory_mb=self.cfg.memory_mb,
        )

    def plan_action(self, existing: Optional[Dict[str, object]],
                    desired_fingerprint: str) -> str:
        """Pure state transition: decide what deploy should do.

        Returns one of: "create", "no-change", "update".
        Foreign containers are rejected before this is called.
        """
        if existing is None:
            return "create"
        labels = self._labels_of(existing)
        state = inspect_state(existing)
        # "starting" is deliberately NOT accepted: a container whose health
        # has not yet been proven must go through the full update path.
        if labels.get(LABEL_FINGERPRINT) == desired_fingerprint and state in (
            "running", "healthy"
        ):
            return "no-change"
        return "update"

    # -- container construction -----------------------------------------------

    def remote_config_path(self, config_sha256: str) -> str:
        """Content-addressed remote path for an uploaded config version.

        Each distinct config content lives at its own path, so deploying a new
        config never overwrites the file still mounted by the old (backup)
        container -- rollback therefore restores the old config too.
        """
        return f"{self.cfg.remote_dir}/config/{config_sha256}"

    def container_config_mount(self) -> str:
        """In-container path the exact desired config file is mounted at."""
        return f"/etc/dynam/{os.path.basename(self.cfg.config_path or 'config')}"

    def build_create_command(self, fingerprint: str, config_sha256: Optional[str],
                             image_id: str) -> str:
        """Build the `docker create` command line (never publishes ports).

        The container is created from the immutable ``sha256:<image_id>``
        reference (already verified against --image-id), not the mutable tag,
        which eliminates the verify-then-create tag TOCTOU window.
        """
        c = self.cfg
        parts: List[str] = ["docker create", "--name", shlex.quote(c.container_name)]
        parts += ["--label", shlex.quote(f"{OWNER_LABEL}={OWNER_VALUE}")]
        parts += ["--label", shlex.quote(f"{LABEL_FINGERPRINT}={fingerprint}")]
        parts += ["--label", shlex.quote(f"{LABEL_IMAGE_ID}={normalize_image_id(image_id)}")]
        if config_sha256:
            parts += ["--label", shlex.quote(f"{LABEL_CONFIG_SHA256}={config_sha256}")]
        parts += ["--label", shlex.quote(f"{LABEL_CREATED}={int(self.now())}")]
        if c.cpus is not None:
            parts += ["--cpus", shlex.quote(str(c.cpus))]
        if c.memory_mb is not None:
            parts += ["--memory", shlex.quote(f"{c.memory_mb}m")]
        if config_sha256:
            # Mount the exact desired, content-addressed config file read-only.
            mount = f"{self.remote_config_path(config_sha256)}:{self.container_config_mount()}:ro"
            parts += ["--volume", shlex.quote(mount)]
        # No --publish / -p: no ports are published by default.
        # No firewall tooling is invoked anywhere.
        if c.health_cmd:
            parts += ["--health-cmd", shlex.quote(" ".join(shlex.quote(x) for x in c.health_cmd))]
            parts += ["--health-interval", "5s", "--health-timeout", "5s",
                      "--health-retries", "3"]
        parts += ["--entrypoint", shlex.quote(c.entrypoint)]
        parts.append(shlex.quote(f"sha256:{normalize_image_id(image_id)}"))
        parts += [shlex.quote(a) for a in c.cmd_args]
        return " ".join(parts)

    # -- health wait -----------------------------------------------------------

    def wait_healthy(self, name: str, timeout_sec: int) -> str:
        """Bounded wait for container health. Returns final status string."""
        deadline = self.now() + timeout_sec
        last = "unknown"
        while self.now() <= deadline:
            inspect = self._docker_inspect(name)
            if inspect is None:
                raise AutoDeployError(f"container '{name}' disappeared during health wait")
            state = inspect_state(inspect)
            if state == "healthy":
                return "healthy"
            if state in ("exited", "dead"):
                raise AutoDeployError(f"container '{name}' is {state} during health wait")
            last = state
            self.sleep(HEALTH_POLL_INTERVAL_SEC)
        raise AutoDeployError(
            f"timed out after {timeout_sec}s waiting for '{name}' to become healthy (last={last})"
        )

    # -- deploy ----------------------------------------------------------------

    def deploy(self) -> Dict[str, object]:
        cfg = self.cfg
        result: Dict[str, object] = {"command": "deploy", "ok": False}
        self.acquire_lock()
        try:
            result["preflight"] = self.preflight()
            image_id = self.verify_image_id()
            result["image_id"] = image_id

            # Hash the local config only; nothing is uploaded until we know an
            # actual change is required (no-change performs no upload).
            config_sha256: Optional[str] = None
            if cfg.config_path:
                config_sha256 = sha256_file(cfg.config_path)
            result["config_sha256"] = config_sha256

            fingerprint = compute_fingerprint(self.desired_spec(config_sha256))
            result["fingerprint"] = fingerprint

            existing = self._docker_inspect(cfg.container_name)
            self._require_owned(existing, cfg.container_name)
            action = self.plan_action(existing, fingerprint)
            result["action"] = action

            if action == "no-change":
                result["ok"] = True
                result["status"] = inspect_state(existing)  # type: ignore[arg-type]
                return result

            # A change is really happening: upload the content-addressed
            # config BEFORE touching the running container.
            if config_sha256:
                self._run(f"mkdir -p {shlex.quote(cfg.remote_dir)}/config")
                self.t.put_file(cfg.config_path or "", self.remote_config_path(config_sha256))

            backup_created = False
            old_config_sha256: Optional[str] = None
            if action == "update":
                # Inspect/reject a foreign backup BEFORE stopping the primary,
                # so a refusal leaves the primary running.
                old_backup = self._docker_inspect(cfg.backup_name)
                if old_backup is not None:
                    self._require_owned(old_backup, cfg.backup_name)
                    self._run(f"docker rm -f {shlex.quote(cfg.backup_name)}")
                old_config_sha256 = self._labels_of(existing).get(LABEL_CONFIG_SHA256)  # type: ignore[arg-type]
                # Safe update: stop and rename the old container to a backup.
                self._run(f"docker stop {shlex.quote(cfg.container_name)}", timeout=120)
                self._run(f"docker rename {shlex.quote(cfg.container_name)} "
                          f"{shlex.quote(cfg.backup_name)}")
                backup_created = True

            create_cmd = self.build_create_command(fingerprint, config_sha256, image_id)
            try:
                self._run(create_cmd)
                self._run(f"docker start {shlex.quote(cfg.container_name)}", timeout=60)
                if cfg.health_cmd:
                    status = self.wait_healthy(cfg.container_name, cfg.health_wait_sec)
                else:
                    status = inspect_state(self._docker_inspect(cfg.container_name))  # type: ignore[arg-type]
                result["status"] = status
            except Exception as exc:
                # Automatic rollback on any creation/health failure.
                # The desired state was NOT reached, so ok stays False even
                # when the rollback succeeds; rollback_ok reports that
                # separately.
                result["rollback"] = True
                result["failure"] = sanitize_text(str(exc), self.secrets)
                self.t.exec(f"docker rm -f {shlex.quote(cfg.container_name)}", timeout=60)
                # The just-uploaded config version is now unreferenced unless
                # the old container uses the same content; clean it up.
                if config_sha256 and config_sha256 != old_config_sha256:
                    self.t.exec(f"rm -f {shlex.quote(self.remote_config_path(config_sha256))}",
                                timeout=30)
                if backup_created:
                    result["rollback_ok"] = self._restore_backup()
                    result["status"] = "rolled-back" if result["rollback_ok"] else "rollback-failed"
                else:
                    result["rollback_ok"] = None  # nothing to restore
                    result["status"] = "failed"
                result["ok"] = False  # desired update failed: never report success
                return result

            # Success: cleanup the backup container and the old config version.
            if backup_created:
                self._run(f"docker rm -f {shlex.quote(cfg.backup_name)}")
                result["backup_removed"] = True
                if old_config_sha256 and old_config_sha256 != config_sha256:
                    self.t.exec(f"rm -f {shlex.quote(self.remote_config_path(old_config_sha256))}",
                                timeout=30)
                    result["old_config_removed"] = True
            result["ok"] = True
            return result
        finally:
            self.release_lock()

    def _restore_backup(self) -> bool:
        """Rename the backup back to the primary name and verify it starts.

        Returns True only if both the rename and the `docker start` succeed;
        failures are reported (rollback-failed) rather than assumed away.
        """
        try:
            ren = self.t.exec(f"docker rename {shlex.quote(self.cfg.backup_name)} "
                              f"{shlex.quote(self.cfg.container_name)}", timeout=60)
            if ren.code != 0:
                return False
            start = self.t.exec(f"docker start {shlex.quote(self.cfg.container_name)}",
                                timeout=60)
            return start.code == 0
        except Exception:
            return False

    # -- status -----------------------------------------------------------------

    def status(self) -> Dict[str, object]:
        result: Dict[str, object] = {"command": "status", "ok": True}
        inspect = self._docker_inspect(self.cfg.container_name)
        if inspect is None:
            result.update({"present": False, "status": "absent"})
            return result
        labels = self._labels_of(inspect)
        result.update({
            "present": True,
            "owned": is_owned(labels),
            "status": inspect_state(inspect),
            "fingerprint": labels.get(LABEL_FINGERPRINT),
            "image_id": labels.get(LABEL_IMAGE_ID),
            "config_sha256": labels.get(LABEL_CONFIG_SHA256),
        })
        return result

    # -- destroy ----------------------------------------------------------------

    def destroy(self) -> Dict[str, object]:
        result: Dict[str, object] = {"command": "destroy", "ok": False}
        self.acquire_lock()
        try:
            removed: List[str] = []
            inspect = self._docker_inspect(self.cfg.container_name)
            if inspect is not None:
                self._require_owned(inspect, self.cfg.container_name)
                self._run(f"docker rm -f {shlex.quote(self.cfg.container_name)}", timeout=120)
                removed.append("container")
            # An owned backup and the managed state (including all
            # content-addressed config versions) are cleaned even when the
            # main container is absent.
            backup = self._docker_inspect(self.cfg.backup_name)
            if backup is not None:
                self._require_owned(backup, self.cfg.backup_name)
                self._run(f"docker rm -f {shlex.quote(self.cfg.backup_name)}")
                removed.append("backup")
            self._run(f"rm -rf {shlex.quote(self.cfg.remote_dir)}")
            removed.append("state")
            result.update({"ok": True,
                           "status": "destroyed" if "container" in removed else "absent",
                           "removed": removed})
            return result
        finally:
            self.release_lock()

    def run(self) -> Dict[str, object]:
        if self.cfg.command == "deploy":
            return self.deploy()
        if self.cfg.command == "status":
            return self.status()
        if self.cfg.command == "destroy":
            return self.destroy()
        raise AutoDeployError(f"unknown command: {self.cfg.command}")


def inspect_state(inspect: Dict[str, object]) -> str:
    """Extract a coarse container state from `docker inspect` JSON."""
    state = inspect.get("State") or {}
    if isinstance(state, dict):
        health = state.get("Health") or {}
        if isinstance(health, dict) and health.get("Status"):
            status = str(health["Status"])
            if status == "healthy":
                return "healthy"
            if status == "starting":
                return "starting"
            if status == "unhealthy":
                return "unhealthy"
        if state.get("Running"):
            return "running"
        status = str(state.get("Status") or "")
        if status in ("exited", "dead", "created", "paused", "restarting"):
            return status
    return "unknown"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def build_arg_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ssh_autodeploy",
        description="Safe standalone SSH AutoDeploy for Dynam (deploy/status/destroy).",
        epilog=(
            "Remote lock: a mkdir-based lock at /run/dynam-autodeploy.lock serializes "
            "operations and is released on every normal exit. If a run is killed hard "
            "and the lock is left behind (stale), verify no autodeploy is running on "
            "the host, then recover with: ssh <host> rmdir /run/dynam-autodeploy.lock"
        ),
    )
    p.add_argument("command", choices=["deploy", "status", "destroy"])
    p.add_argument("--host", required=True, help="remote host (no defaults, never embedded)")
    p.add_argument("--port", type=int, default=22)
    p.add_argument("--user", default="root")
    p.add_argument("--host-key-sha256", required=True,
                   help="pinned SHA256 fingerprint (hex) of the SSH host key; mandatory")
    p.add_argument("--container-name", default=DEFAULT_CONTAINER_NAME)
    p.add_argument("--image", default="dynam-dpi:client-debian11")
    p.add_argument("--image-id", default="",
                   help="pinned docker image ID (sha256) required for deploy")
    p.add_argument("--config", dest="config_path", default=None,
                   help="local config file to upload (SFTP, mounted read-only)")
    p.add_argument("--entrypoint", default="/usr/local/bin/ncp",
                   help="image entrypoint override (default: /usr/local/bin/ncp)")
    p.add_argument("--cmd-args", default="", help="arguments passed after the entrypoint")
    p.add_argument("--health-cmd", default="/usr/local/bin/ncp --help",
                   help="container healthcheck command (empty string disables)")
    p.add_argument("--cpus", type=float, default=None, help="CPU limit (e.g. 1.5)")
    p.add_argument("--memory-mb", type=int, default=None, help="RAM limit in MB")
    p.add_argument("--health-wait-sec", type=int, default=HEALTH_WAIT_DEFAULT_SEC,
                   help="bounded wait for the container to become healthy")
    p.add_argument("--min-disk-mb", type=int, default=MIN_DISK_MB)
    p.add_argument("--min-memory-mb", type=int, default=MIN_MEMORY_MB)
    # NOTE: there is deliberately NO --password option. The password comes
    # only from the DYNAM_SSH_PASSWORD environment variable.
    return p


def config_from_args(args: argparse.Namespace) -> DeployConfig:
    return DeployConfig(
        command=args.command,
        container_name=args.container_name,
        image=args.image,
        image_id=args.image_id,
        config_path=args.config_path,
        entrypoint=args.entrypoint,
        cmd_args=shlex.split(args.cmd_args),
        health_cmd=shlex.split(args.health_cmd) if args.health_cmd.strip() else [],
        cpus=args.cpus,
        memory_mb=args.memory_mb,
        health_wait_sec=args.health_wait_sec,
        min_disk_mb=args.min_disk_mb,
        min_memory_mb=args.min_memory_mb,
    )


def main(argv: Optional[Sequence[str]] = None) -> int:
    args = build_arg_parser().parse_args(argv)
    cfg = config_from_args(args)
    # Seed the redaction list BEFORE constructing the transport so that even
    # handshake/authentication errors raised during Paramiko setup (which may
    # embed the password) are sanitized in the JSON output.
    secrets: List[str] = []
    env_password = os.environ.get("DYNAM_SSH_PASSWORD")
    if env_password:
        secrets.append(env_password)
    transport: Optional[Transport] = None
    try:
        transport = ParamikoTransport(args.host, args.port, args.user, args.host_key_sha256)
        for s in getattr(transport, "secrets", []):
            if s and s not in secrets:
                secrets.append(s)
        result = Deployer(transport, cfg, secrets=secrets).run()
        ok = bool(result.get("ok"))
    except AutoDeployError as exc:
        result = {"command": cfg.command, "ok": False,
                  "error": sanitize_text(str(exc), secrets)}
        ok = False
    except Exception as exc:  # unexpected: still sanitized, still JSON
        result = {"command": cfg.command, "ok": False,
                  "error": f"unexpected: {sanitize_text(str(exc), secrets)}"}
        ok = False
    finally:
        if transport is not None:
            transport.close()
    print(json.dumps(sanitize_json(result, secrets), indent=2, sort_keys=True))
    return 0 if ok else 1


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
