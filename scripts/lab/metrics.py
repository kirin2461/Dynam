#!/usr/bin/env python3
"""
metrics.py — curl-based measurement runner for the Dynam DPI lab.

Executes a curl case N times (direct or through the ncp proxy), collects
per-run timings/counters, samples per-core CPU (and optionally the ncp
process CPU) over the whole window, aggregates statistics and emits a JSON
report plus a compact markdown table.

Usage:
    metrics.py run --name CASE --url URL [options]
    metrics.py aggregate FILE.json [FILE2.json ...] [--md out.md]

Per-run record:
    {success, http_code, time_connect, time_appconnect (TLS handshake done),
     time_starttransfer (TTFB), time_total, speed_download, size_download,
     content_type, retransmits, err}

Aggregate:
    {runs, success_rate, handshake_median/p95, ttfb_median/p95,
     total_median, speed_median, retransmits_total}

Retransmits per run (best effort, in priority order):
    1. --pcap FILE  -> count tcp.analysis.retransmission via tshark
                       (pcap-wide total, attached to the last run)
    2. ss -tin polled while curl runs; last sample for the destination
       socket gives the kernel retrans counter.

Only the python3 standard library + curl (+ optional ss/tshark) are used.
"""

import argparse
import json
import os
import re
import statistics
import subprocess
import sys
import tempfile
import threading
import time
from urllib.parse import urlparse

SUCCESS_MARKER_DEFAULT = None  # set via --expect-marker (e.g. DYNAM-TESTBED-OK)


# --------------------------------------------------------------------------
# Statistics
# --------------------------------------------------------------------------

def percentile(values, pct):
    """Percentile with linear interpolation (pct in [0, 100])."""
    vals = sorted(v for v in values if v is not None)
    if not vals:
        return None
    if len(vals) == 1:
        return vals[0]
    rank = (len(vals) - 1) * pct / 100.0
    low = int(rank)
    high = min(low + 1, len(vals) - 1)
    frac = rank - low
    return vals[low] + (vals[high] - vals[low]) * frac


def median(values):
    vals = [v for v in values if v is not None]
    return statistics.median(vals) if vals else None


def aggregate(runs):
    """Aggregate per-run records into summary statistics."""
    ok = [r for r in runs if r.get("success")]
    def col(name, src=None):
        return [r.get(name) for r in (src if src is not None else runs)]
    retrans = [r.get("retransmits") for r in runs
               if r.get("retransmits") is not None]
    return {
        "runs": len(runs),
        "successes": len(ok),
        "success_rate": (len(ok) / len(runs)) if runs else None,
        # Handshake/TTFB only make sense for successful TLS runs.
        "handshake_median": median(col("time_appconnect", ok)),
        "handshake_p95": percentile(col("time_appconnect", ok), 95),
        "ttfb_median": median(col("time_starttransfer", ok)),
        "ttfb_p95": percentile(col("time_starttransfer", ok), 95),
        "connect_median": median(col("time_connect", ok)),
        "total_median": median(col("time_total", ok)),
        "total_p95": percentile(col("time_total", ok), 95),
        "speed_median": median(col("speed_download", ok)),
        "retransmits_total": sum(retrans) if retrans else None,
    }


# --------------------------------------------------------------------------
# CPU sampling
# --------------------------------------------------------------------------

def read_proc_stat_cores():
    """Per-core jiffies from /proc/stat: {core: (busy, total)}."""
    cores = {}
    with open("/proc/stat") as fh:
        for line in fh:
            parts = line.split()
            if not parts or not re.fullmatch(r"cpu\d+", parts[0]):
                continue
            vals = [int(x) for x in parts[1:]]
            idle = vals[3] + (vals[4] if len(vals) > 4 else 0)  # idle+iowait
            total = sum(vals)
            cores[parts[0]] = (total - idle, total)
    return cores


def read_pid_jiffies(pid):
    """utime+stime of a process from /proc/<pid>/stat (jiffies)."""
    with open("/proc/%d/stat" % pid) as fh:
        data = fh.read()
    # comm may contain spaces/parens — cut it out first.
    rest = data[data.rindex(")") + 2:].split()
    utime, stime = int(rest[11]), int(rest[12])
    return utime + stime


class CpuSampler:
    """Sample /proc/stat (per core) and /proc/<pid>/stat around a window."""

    def __init__(self, pid=None):
        self.pid = pid
        self.hz = os.sysconf("SC_CLK_TCK")
        self.t0 = None
        self.cores0 = None
        self.pid0 = None

    def start(self):
        self.t0 = time.monotonic()
        self.cores0 = read_proc_stat_cores()
        self.pid0 = self._safe_pid_jiffies()

    def _safe_pid_jiffies(self):
        if self.pid is None:
            return None
        try:
            return read_pid_jiffies(self.pid)
        except (OSError, ValueError, IndexError):
            return None

    def stop(self):
        dt = time.monotonic() - self.t0
        cores1 = read_proc_stat_cores()
        pid1 = self._safe_pid_jiffies()
        per_core = {}
        for core, (busy0, total0) in self.cores0.items():
            if core not in cores1:
                continue
            busy1, total1 = cores1[core]
            dtotal = total1 - total0
            per_core[core] = (round(100.0 * (busy1 - busy0) / dtotal, 2)
                              if dtotal > 0 else None)
        result = {
            "window_seconds": round(dt, 3),
            "per_core_busy_percent": per_core,
            "pid": self.pid,
            "ncp_cpu_percent_total": None,
        }
        if self.pid0 is not None and pid1 is not None and dt > 0:
            # % of one CPU; >100 possible on multicore.
            result["ncp_cpu_percent_total"] = round(
                100.0 * (pid1 - self.pid0) / (self.hz * dt), 2)
        return result


# --------------------------------------------------------------------------
# Retransmission sampling
# --------------------------------------------------------------------------

_RETRANS_RE = re.compile(r"\bretrans:(\d+)/(\d+)")


def ss_retransmits(dst):
    """Parse `ss -tin` for sockets to dst; return total retrans or None."""
    try:
        out = subprocess.run(["ss", "-tin"], stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=5)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = out.stdout.decode(errors="replace")
    best = None
    lines = text.splitlines()
    for i, line in enumerate(lines):
        # Header line of a socket entry ends with "peer_ip:port".
        fields = line.split()
        if len(fields) >= 5 and dst in fields[-1]:
            m = _RETRANS_RE.search(line)
            if not m and i + 1 < len(lines):
                m = _RETRANS_RE.search(lines[i + 1])
            if m:
                total = int(m.group(2))
                best = total if best is None else max(best, total)
    return best


class SsPoller(threading.Thread):
    """Poll ss -tin while curl runs; keep the last retrans count seen."""

    def __init__(self, dst, interval=0.2):
        super().__init__(daemon=True)
        self.dst = dst
        self.interval = interval
        self.stop_event = threading.Event()
        self.last = None

    def run(self):
        while not self.stop_event.is_set():
            val = ss_retransmits(self.dst)
            if val is not None:
                self.last = val
            self.stop_event.wait(self.interval)

    def finish(self):
        self.stop_event.set()
        # One final sample right after curl exits (socket may still exist).
        val = ss_retransmits(self.dst)
        if val is not None:
            self.last = val
        return self.last


def pcap_retransmits(pcap):
    """Count tcp.analysis.retransmission frames in a pcap via tshark."""
    try:
        out = subprocess.run(
            ["tshark", "-r", pcap, "-n", "-Y",
             "tcp.analysis.retransmission", "-T", "fields", "-e",
             "frame.number"],
            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=120)
    except (OSError, subprocess.TimeoutExpired):
        return None
    if out.returncode != 0:
        return None
    return sum(1 for l in out.stdout.decode(errors="replace").splitlines()
               if l.strip())


# --------------------------------------------------------------------------
# curl runner
# --------------------------------------------------------------------------

CURL_WRITE_OUT = (
    '{"http_code": %{http_code}, "time_connect": %{time_connect}, '
    '"time_appconnect": %{time_appconnect}, '
    '"time_starttransfer": %{time_starttransfer}, "time_total": %{time_total},'
    ' "speed_download": %{speed_download}, "size_download": %{size_download},'
    ' "content_type": "%{content_type}"}'
)


def run_curl_once(url, proxy=None, timeout=60, insecure=False,
                  marker=None, extra_args=None):
    """Run curl once; return a per-run record dict."""
    body_file = None
    cmd = ["curl", "-sS", "--connect-timeout", str(timeout),
           "--max-time", str(timeout), "-w", CURL_WRITE_OUT]
    if insecure:
        cmd.append("-k")
    if proxy:
        cmd += ["-x", proxy]
    if extra_args:
        cmd += extra_args
    if marker:
        fd, body_file = tempfile.mkstemp(prefix="metrics-body-")
        os.close(fd)
        cmd += ["-o", body_file]
    else:
        cmd += ["-o", os.devnull]
    cmd.append(url)

    t0 = time.monotonic()
    proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    wall = time.monotonic() - t0

    rec = {"success": False, "http_code": None, "time_connect": None,
           "time_appconnect": None, "time_starttransfer": None,
           "time_total": None, "speed_download": None, "size_download": None,
           "content_type": None, "retransmits": None, "err": None}

    err = proc.stderr.decode(errors="replace").strip()
    try:
        data = json.loads(proc.stdout.decode(errors="replace").strip()
                          or "{}")
    except json.JSONDecodeError:
        data = {}
    for key in ("http_code", "time_connect", "time_appconnect",
                "time_starttransfer", "time_total", "speed_download",
                "size_download", "content_type"):
        val = data.get(key)
        rec[key] = val if val != "" else None
    if rec["http_code"] == 0:
        rec["http_code"] = None

    if proc.returncode != 0:
        rec["err"] = "curl rc=%d: %s" % (proc.returncode, err[:300])
    elif rec["http_code"] is None or not (200 <= rec["http_code"] < 400):
        rec["err"] = "unexpected http_code=%s" % rec["http_code"]
    else:
        rec["success"] = True

    if marker and body_file is not None:
        try:
            with open(body_file, "rb") as fh:
                body = fh.read()
            if marker.encode() not in body:
                rec["success"] = False
                rec["err"] = "success marker %r not found in body" % marker
        except OSError as exc:
            rec["success"] = False
            rec["err"] = "cannot read body: %s" % exc
    if body_file:
        try:
            os.unlink(body_file)
        except OSError:
            pass
    rec["wall_time"] = round(wall, 3)
    return rec


def run_case(name, url, runs, proxy=None, timeout=60, insecure=False,
             marker=None, extra_args=None, pid=None, pcap=None,
             ss_dst=None, pause=0.0, log=print):
    """Execute the case N times, sample CPU over the window, aggregate."""
    if ss_dst is None:
        u = urlparse(url)
        port = u.port or (443 if u.scheme == "https" else 80)
        ss_dst = "%s:%d" % (u.hostname, port)

    sampler = CpuSampler(pid=pid)
    sampler.start()
    records = []
    for i in range(1, runs + 1):
        poller = SsPoller(ss_dst)
        poller.start()
        rec = run_curl_once(url, proxy=proxy, timeout=timeout,
                            insecure=insecure, marker=marker,
                            extra_args=extra_args)
        rec["retransmits"] = poller.finish()
        poller.join(timeout=2)
        rec["run"] = i
        records.append(rec)
        log("run %d/%d: success=%s code=%s total=%ss retrans=%s %s"
            % (i, runs, rec["success"], rec["http_code"],
               rec["time_total"], rec["retransmits"], rec["err"] or ""))
        if pause and i < runs:
            time.sleep(pause)
    cpu = sampler.stop()

    if pcap:
        total = pcap_retransmits(pcap)
        if total is not None and records:
            # pcap counter is window-wide: attach to the last run so that
            # retransmits_total in the aggregate reflects it exactly once.
            records[-1]["retransmits"] = total

    return {
        "case": name,
        "url": url,
        "proxy": proxy,
        "runs": records,
        "aggregate": aggregate(records),
        "cpu": cpu,
    }


# --------------------------------------------------------------------------
# Markdown report
# --------------------------------------------------------------------------

def _fmt(val, nd=3):
    if val is None:
        return "-"
    if isinstance(val, float):
        return ("%.*f" % (nd, val)).rstrip("0").rstrip(".")
    return str(val)


def markdown_row(case):
    agg = case["aggregate"]
    cpu = case.get("cpu") or {}
    cells = [
        case["case"],
        _fmt(agg["runs"], 0),
        _fmt(100 * agg["success_rate"], 1) + "%"
            if agg["success_rate"] is not None else "-",
        _fmt(agg["handshake_median"]), _fmt(agg["handshake_p95"]),
        _fmt(agg["ttfb_median"]), _fmt(agg["ttfb_p95"]),
        _fmt(agg["total_median"]),
        _fmt(agg["speed_median"], 0),
        _fmt(agg["retransmits_total"], 0),
        _fmt(cpu.get("ncp_cpu_percent_total"), 1),
    ]
    return "| " + " | ".join(cells) + " |"


MD_HEADER = (
    "| case | runs | success | handshake p50 | handshake p95 | ttfb p50 "
    "| ttfb p95 | total p50 | speed med (B/s) | retrans | ncp cpu% |\n"
    "|---|---|---|---|---|---|---|---|---|---|---|"
)


def markdown_table(cases):
    lines = [MD_HEADER]
    lines += [markdown_row(c) for c in cases]
    return "\n".join(lines) + "\n"


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

def cmd_run(args):
    result = run_case(
        name=args.name, url=args.url, runs=args.runs, proxy=args.proxy,
        timeout=args.timeout, insecure=args.insecure,
        marker=args.expect_marker, extra_args=args.curl_arg or None,
        pid=args.pid, pcap=args.pcap, ss_dst=args.ss_dst, pause=args.pause,
        log=lambda m: print(m, file=sys.stderr))
    text = json.dumps(result, indent=2)
    md = markdown_table([result])
    if args.json:
        with open(args.json, "w") as fh:
            fh.write(text + "\n")
    else:
        print(text)
    if args.md:
        with open(args.md, "w") as fh:
            fh.write(md)
    sys.stderr.write("\n" + md)
    # Exit non-zero if nothing succeeded — suites key off this.
    return 0 if result["aggregate"]["successes"] > 0 else 1


def cmd_aggregate(args):
    cases = []
    for path in args.files:
        with open(path) as fh:
            cases.append(json.load(fh))
    md = markdown_table(cases)
    combined_runs = []
    for c in cases:
        combined_runs.extend(c.get("runs", []))
    out = {
        "cases": [{"case": c["case"], "aggregate": c["aggregate"]}
                  for c in cases],
        "combined": aggregate(combined_runs),
    }
    if args.md:
        with open(args.md, "w") as fh:
            fh.write(md)
    print(md)
    print(json.dumps(out, indent=2))
    return 0


def main(argv=None):
    ap = argparse.ArgumentParser(
        description="curl-based metrics runner for the Dynam DPI lab")
    sub = ap.add_subparsers(dest="command", required=True)

    rp = sub.add_parser("run", help="run a measurement case")
    rp.add_argument("--name", required=True, help="case name")
    rp.add_argument("--url", required=True, help="target URL")
    rp.add_argument("--proxy", help="curl -x proxy spec, "
                                    "e.g. socks5h://127.0.0.1:1080")
    rp.add_argument("--runs", type=int, default=10, help="repetitions")
    rp.add_argument("--timeout", type=int, default=60,
                    help="curl connect/max timeout, seconds")
    rp.add_argument("--insecure", action="store_true",
                    help="curl -k (self-signed testbed certs)")
    rp.add_argument("--expect-marker",
                    help="success marker string required in the body "
                         "(e.g. DYNAM-TESTBED-OK)")
    rp.add_argument("--pid", type=int,
                    help="ncp process id for CPU accounting")
    rp.add_argument("--pcap", help="pcap of the run; retransmits counted "
                                   "via tshark instead of ss")
    rp.add_argument("--ss-dst", help="override ss -tin match (host:port)")
    rp.add_argument("--pause", type=float, default=0.0,
                    help="pause between runs, seconds")
    rp.add_argument("--curl-arg", action="append",
                    help="extra raw curl argument (repeatable)")
    rp.add_argument("--json", help="write JSON report here "
                                   "(default: stdout)")
    rp.add_argument("--md", help="write markdown table here")
    rp.set_defaults(func=cmd_run)

    gp = sub.add_parser("aggregate", help="merge several run reports")
    gp.add_argument("files", nargs="+", help="JSON reports from `run`")
    gp.add_argument("--md", help="write markdown table here")
    gp.set_defaults(func=cmd_aggregate)

    args = ap.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
