#!/usr/bin/env -S uv run --quiet --script
# /// script
# requires-python = ">=3.9"
# dependencies = []
# ///
"""Read-only macOS glitch scan.

Looks for the evidence trail of hangs and stuck system services:

  1. System basics (macOS version, uptime, memory, swap, disk).
  2. Crash/hang reports in DiagnosticReports, grouped, with watchdog
     (0x8BADF00D) hangs told apart from real crashes.
  3. A live `sample` of key per-user system daemons, flagging threads that
     sat in a blocking call for the whole window, and "pile-ups" where
     several XPC clients queue behind one stuck request.
  4. Optional: recent sandbox mach-lookup denials from the unified log.

It never kills, restarts, or changes anything. Python standard library only;
runs with `uv run glitch_scan.py` or plain `python3 glitch_scan.py`.
"""

from __future__ import annotations

import argparse
import concurrent.futures as cf
import datetime as dt
import json
import os
import re
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict
from pathlib import Path

SAMPLE = "/usr/bin/sample"  # full path: Homebrew can shadow `sample`
LOG = "/usr/bin/log"  # full path: zsh has a `log` builtin

# Per-user daemons that many apps talk to over XPC. When one of these wedges,
# several unrelated apps break at once. Only the copies owned by the current
# user are sampled (sampling root processes needs sudo).
DEFAULT_DAEMONS = [
    "ctkd", "coreauthd", "secd", "trustd", "akd",
    "identityservicesd", "imagent", "IMDPersistenceAgent", "transparencyd",
    "callservicesd", "contactsd", "accountsd", "CalendarAgent",
    "cloudd", "bird", "networkserviceproxy", "nsurlsessiond",
    "sharingd", "rapportd", "useractivityd",
]

# Leaf frames that mean "this thread is waiting on something".
BLOCKING = [
    ("xpc_connection_send_message_with_reply_sync", "sync XPC call, waiting for another process"),
    ("__NSXPCCONNECTION_IS_WAITING_FOR_A_SYNCHRONOUS_REPLY__", "sync XPC call, waiting for another process"),
    ("_dispatch_sync_f_slow", "waiting for a dispatch queue held elsewhere"),
    ("__DISPATCH_WAIT_FOR_QUEUE__", "waiting for a dispatch queue held elsewhere"),
    ("_dispatch_event_loop_wait_for_ownership", "waiting for a dispatch queue held elsewhere"),
    ("__ulock_wait", "waiting for a lock"),
    ("__psynch_mutexwait", "waiting for a lock"),
    ("_os_unfair_lock_lock_slow", "waiting for a lock"),
    ("dispatch_semaphore_wait", "waiting on a semaphore"),
    ("dispatch_group_wait", "waiting on a dispatch group"),
    ("__semwait_signal", "sleeping, possibly a retry loop"),
]

# Frames that are plumbing, not a useful "what was it doing" hint.
PLUMBING = re.compile(
    r"\(in (libsystem_\w+|libdispatch|libxpc|libc\+\+|libobjc|libswiftDispatch|dyld)"
    r"|_dispatch_|_os_|__CFRunLoop|CFRunLoopRun|_CF_forwarding|___forwarding___"
    r"|NSXPCConnection _send|_NSXPCDistantObject|__NSXPCCONNECTION|NSRunLoop|NSInvocation|__invoking___"
)
PLUMBING_LIB = re.compile(r"\(in (libsystem_\w+|libdispatch|libxpc|libc\+\+|libobjc|libswiftDispatch|dyld|CoreFoundation|Foundation)")


def run(cmd: list[str], timeout: int = 60) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except (OSError, subprocess.TimeoutExpired):
        return ""


# ---------------------------------------------------------------- system ----

def system_info() -> dict:
    info: dict = {}
    info["macos"] = f'{run(["sw_vers", "-productVersion"]).strip()} ({run(["sw_vers", "-buildVersion"]).strip()})'
    boot = run(["sysctl", "-n", "kern.boottime"])
    m = re.search(r"sec = (\d+)", boot)
    if m:
        booted = dt.datetime.fromtimestamp(int(m.group(1)))
        info["booted"] = booted.strftime("%Y-%m-%d %H:%M")
        info["uptime_days"] = round((dt.datetime.now() - booted).total_seconds() / 86400, 1)
    m = re.search(r"(\d+)%", run(["memory_pressure", "-Q"]))
    info["memory_free_pct"] = int(m.group(1)) if m else None
    info["swap"] = run(["sysctl", "-n", "vm.swapusage"]).strip()
    disks = {}
    for line in run(["df", "-PHl", "/", str(Path.home())]).splitlines()[1:]:
        parts = line.split(None, 5)  # Filesystem Size Used Avail Capacity Mounted-on
        if len(parts) == 6:
            disks[parts[5]] = {"mount": parts[5], "avail": parts[3], "used_pct": int(parts[4].rstrip("%"))}
    info["disks"] = list(disks.values())
    m = re.search(r"total = ([\d.]+)M\s+used = ([\d.]+)M", info["swap"])
    info["swap_used_pct"] = round(100 * float(m.group(2)) / float(m.group(1))) if m and float(m.group(1)) else None
    top = run(["ps", "-Ao", "pcpu=,comm="]).splitlines()
    rows = []
    for line in top:
        parts = line.strip().split(None, 1)
        if len(parts) == 2:
            try:
                rows.append((float(parts[0]), Path(parts[1]).name))
            except ValueError:
                pass
    info["top_cpu"] = [f"{name} {cpu:.0f}%" for cpu, name in sorted(rows, reverse=True)[:5]]
    return info


# --------------------------------------------------------------- reports ----

REPORT_DIRS = [Path.home() / "Library/Logs/DiagnosticReports", Path("/Library/Logs/DiagnosticReports")]
NAME_RE = re.compile(r"^(.+?)[-_](\d{4}-\d{2}-\d{2})-(\d{6})")


def parse_ips(path: Path) -> dict:
    out: dict = {}
    try:
        text = path.read_text(errors="replace")
    except OSError:
        return {"unreadable": True}
    head, _, body = text.partition("\n")
    try:
        out["name"] = json.loads(head).get("app_name") or json.loads(head).get("name")
    except json.JSONDecodeError:
        pass
    if "8BADF00D" in text.upper():
        out["watchdog"] = True
    m = re.search(r"Elapsed application CPU time \(seconds\): ([\d.]+)", text)
    if m:
        out["app_cpu_s"] = float(m.group(1))
    m = re.search(r"allowance of ([\d.]+) seconds", text)
    if m:
        out["wall_s"] = float(m.group(1))
    try:
        b = json.loads(body)
    except json.JSONDecodeError:
        m = re.search(r"Exception Type:\s+(.+)", text)
        if m:
            out["exception"] = m.group(1).strip()
        return out
    ex = b.get("exception") or {}
    out["exception"] = " ".join(str(x) for x in (ex.get("type"), ex.get("signal")) if x)
    images = b.get("usedImages") or []
    for t in b.get("threads") or []:
        if not t.get("triggered"):
            continue
        frames = []
        for f in t.get("frames", []):
            sym = f.get("symbol")
            idx = f.get("imageIndex")
            img = images[idx].get("name") if isinstance(idx, int) and idx < len(images) else None
            label = sym or (f"??? (in {img})" if img else None)
            if label and not re.match(r"(kevent|_dispatch_|__DISPATCH|mach_msg|__ulock|__psynch)", label):
                frames.append(label)
        out["stack_hint"] = frames[:6]
        break
    return out


def scan_reports(days: int) -> list[dict]:
    cutoff = dt.datetime.now() - dt.timedelta(days=days)
    groups: dict = defaultdict(lambda: {"count": 0, "dates": []})
    for d in REPORT_DIRS:
        try:
            entries = list(d.iterdir())
        except OSError:
            continue
        for p in entries:
            m = NAME_RE.match(p.name)
            if not m or p.is_dir():
                continue
            when = dt.datetime.strptime(m.group(2) + m.group(3), "%Y-%m-%d%H%M%S")
            if when < cutoff:
                continue
            proc = re.sub(r"^ExcResource_", "", m.group(1))
            if p.suffix == ".ips":
                meta = parse_ips(p)
                kind = "hang (watchdog kill)" if meta.get("watchdog") else "crash"
            elif p.name.endswith(".hang"):
                meta, kind = {}, "hang report"
            elif p.name.endswith(".spin"):
                meta, kind = {}, "spin report"
            elif ".diag" in p.name:
                meta = {}
                res = re.search(r"(cpu|wakeups|diskwrites|memory)_resource", p.name)
                kind = f"resource report ({res.group(1)})" if res else "resource report"
            else:
                continue
            g = groups[(proc, kind)]
            g["count"] += 1
            g["dates"].append(when)
            if meta and (not g.get("meta") or when >= max(g["dates"])):
                g["meta"] = meta
                g["latest_file"] = str(p)
    out = []
    for (proc, kind), g in groups.items():
        dates = sorted(g["dates"])
        out.append({
            "process": proc, "kind": kind, "count": g["count"],
            "first": dates[0].strftime("%Y-%m-%d %H:%M"), "last": dates[-1].strftime("%Y-%m-%d %H:%M"),
            **({"details": g["meta"]} if g.get("meta") else {}),
            **({"latest_file": g["latest_file"]} if g.get("latest_file") else {}),
        })
    rank = {"hang (watchdog kill)": 0, "hang report": 1, "crash": 2, "spin report": 3}
    out.sort(key=lambda r: (rank.get(r["kind"], 9), -r["count"], r["process"]))
    return out


# -------------------------------------------------------------- sampling ----

THREAD_RE = re.compile(r"^    (\d+) Thread_(\d+)(.*)$")
FRAME_RE = re.compile(r"^(\s*[+!:| ]*)(\d+) (.+?)\s*$")
CLIENT_PID_RE = re.compile(r"NSXPCConnection\..*?\.(\d+)\s*(?:\(|$)")


def processes() -> list[dict]:
    me = os.getuid()
    out = []
    for line in run(["ps", "-Ao", "pid=,uid=,etime=,comm="]).splitlines():
        parts = line.split(None, 3)
        if len(parts) == 4 and parts[0].isdigit():
            out.append({"pid": int(parts[0]), "uid": int(parts[1]), "etime": parts[2],
                        "path": parts[3], "name": Path(parts[3]).name, "mine": int(parts[1]) == me})
    return out


def parse_sample(text: str) -> dict:
    """Return threads that spent (almost) the whole window in a blocking call."""
    lines = text.splitlines()
    try:
        start = next(i for i, l in enumerate(lines) if l.startswith("Call graph:"))
    except StopIteration:
        return {"error": "no call graph in sample output"}
    threads, cur = [], None
    for line in lines[start + 1:]:
        if line.startswith("Total number in stack") or (line and not line.startswith(" ")):
            break
        tm = THREAD_RE.match(line)
        if tm:
            cur = {"count": int(tm.group(1)), "header": tm.group(3).strip(), "stack": [], "blocked": None}
            threads.append(cur)
            continue
        fm = FRAME_RE.match(line)
        if not fm or cur is None:
            continue
        indent, count, frame = len(fm.group(1)), int(fm.group(2)), fm.group(3)
        frame = re.sub(r"\s+\[0x[0-9a-f]+(,0x[0-9a-f]+)*\]$", "", frame)
        frame = re.sub(r"\s+load address 0x[0-9a-f]+ \+ 0x[0-9a-f]+", "", frame)
        frame = re.sub(r"\s+\+ \d+$", "", frame)
        while cur["stack"] and cur["stack"][-1][0] >= indent:
            cur["stack"].pop()
        cur["stack"].append((indent, frame))
        if cur["blocked"] is None and count >= max(2, int(cur["count"] * 0.95)):
            for marker, meaning in BLOCKING:
                if marker in frame:
                    path = [f for _, f in cur["stack"]]
                    hints = [f for f in path if not PLUMBING.search(f) and not f.startswith("???")]
                    if not hints:  # no symbols: fall back to "??? (in Framework)" frames
                        hints = [f for f in path if not PLUMBING_LIB.search(f)]
                    cur["blocked"] = {"call": marker, "meaning": meaning, "context": hints[-4:] or path[-4:]}
                    break
    total = max((t["count"] for t in threads), default=0)
    blocked = []
    for t in threads:
        if t["blocked"] and t["count"] >= total * 0.9:
            q = t["header"]
            m = CLIENT_PID_RE.search(q + " ")
            blocked.append({"queue": q, **t["blocked"], **({"client_pid": int(m.group(1))} if m else {})})
    return {"samples": total, "blocked_threads": blocked}


def sample_one(proc: dict, seconds: int) -> dict:
    with tempfile.TemporaryDirectory() as tmp:
        out = Path(tmp) / "s.txt"
        run([SAMPLE, str(proc["pid"]), str(seconds), "-file", str(out)], timeout=seconds + 60)
        try:
            text = out.read_text(errors="replace")
        except OSError:
            return {**proc, "error": "sample failed (permission or process exited)"}
    return {**proc, **parse_sample(text)}


def scan_daemons(names: list[str], extra_pids: list[int], seconds: int) -> tuple[list[dict], list[str]]:
    """Sample matching per-user processes; return (results, names not running)."""
    procs = processes()
    by_pid = {p["pid"]: p for p in procs}
    wanted = [p for p in procs if p["mine"] and p["name"] in set(names)]
    wanted += [by_pid[pid] for pid in extra_pids if pid in by_pid and by_pid[pid] not in wanted]
    with cf.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(lambda p: sample_one(p, seconds), wanted))
    for r in results:
        for b in r.get("blocked_threads", []):
            if "client_pid" in b:
                c = by_pid.get(b["client_pid"])
                b["client"] = c["name"] if c else "(exited process)"
        # Pile-up: several XPC clients stuck on the same code path.
        clients = [b for b in r.get("blocked_threads", []) if "client_pid" in b]
        sig = Counter(" > ".join(b["context"][-2:]) for b in clients)
        piles = [{"context": k, "clients": n} for k, n in sig.items() if n >= 2]
        if piles:
            # The request everyone queues behind is usually the one client thread
            # that is itself waiting on another process.
            heads = [b for b in clients if b["call"] in (BLOCKING[0][0], BLOCKING[1][0])]
            for p in piles:
                if heads:
                    h = heads[0]
                    p["head"] = {"client": h.get("client"), "client_pid": h["client_pid"],
                                 "waiting_in": " > ".join(h["context"][-2:])}
            r["pileups"] = piles
    results.sort(key=lambda r: (-len(r.get("pileups", [])), -len(r.get("blocked_threads", []))))
    return results, sorted(set(names) - {p["name"] for p in wanted})


# ------------------------------------------------------------------ logs ----

def scan_logs(minutes: int) -> list[dict]:
    text = run([LOG, "show", "--last", f"{minutes}m", "--style", "compact",
                "--predicate", 'eventMessage CONTAINS "deny(1) mach-lookup"'], timeout=300)
    pairs: Counter = Counter()
    for line in text.splitlines():
        m = re.search(r"Sandbox: ([^(]+)\(\d+\) deny\(1\) mach-lookup (\S+)", line)
        if m:
            pairs[(m.group(1), m.group(2))] += 1
    return [{"process": p, "service": s, "count": n} for (p, s), n in pairs.most_common(12)]


# ---------------------------------------------------------------- report ----

def flag_summary(res: dict) -> list[str]:
    """The few findings worth reading first."""
    flags = []
    for r in res["daemons"]:
        for p in r.get("pileups", []):
            head = f", head: request from {p['head']['client']}" if p.get("head") else ""
            flags.append(f"PILE-UP in {r['name']}: {p['clients']} clients stuck behind one request{head}. Prime suspect.")
    for r in res["reports"]:
        if r["kind"] == "hang (watchdog kill)":
            flags.append(f"{r['process']} was killed for hanging {r['count']} time(s) since {r['first']}.")
        elif r["kind"] == "crash" and r["count"] >= 3:
            flags.append(f"{r['process']} crashed {r['count']} times since {r['first']}.")
    blocked = [r["name"] for r in res["daemons"] if r.get("blocked_threads") and not r.get("pileups")]
    if blocked:
        flags.append(f"Blocked threads in: {', '.join(blocked)}. Re-run to see if it persists.")
    s = res["system"]
    if (s.get("swap_used_pct") or 0) >= 75:
        flags.append(f"Swap is {s['swap_used_pct']}% full, so the system is short on memory.")
    if s.get("memory_free_pct") is not None and s["memory_free_pct"] < 10:
        flags.append(f"Only {s['memory_free_pct']}% memory free.")
    for d in s.get("disks", []):
        if d["used_pct"] >= 90:
            flags.append(f"Disk {d['mount']} is {d['used_pct']}% full.")
    for l in res.get("logs") or []:
        if l["count"] >= 100:
            flags.append(f"{l['process']} was denied {l['service']} {l['count']} times in {res['log_minutes']} min.")
    return flags


def render(res: dict) -> str:
    out = ["# Mac glitch scan", ""]
    s = res["system"]
    flags = flag_summary(res)
    out += ["## Flags"] + ([f"- {f}" for f in flags] or ["- Nothing stands out."]) + [""]
    out += ["## System", f"- macOS {s.get('macos')}, up {s.get('uptime_days')} days (booted {s.get('booted')})",
            f"- Memory free: {s.get('memory_free_pct')}%   Swap: {s.get('swap')}",
            *[f"- Disk {d['mount']}: {d['used_pct']}% used, {d['avail']} free" for d in s.get("disks", [])],
            f"- Top CPU: {', '.join(s.get('top_cpu', []))}", ""]

    out.append(f"## Crash and hang reports (last {res['days']} days)")
    reps = res["reports"]
    if not reps:
        out.append("- None found.")
    for r in reps:
        line = f"- **{r['process']}**: {r['count']} x {r['kind']}, {r['first']} to {r['last']}"
        d = r.get("details", {})
        if d.get("watchdog") and d.get("app_cpu_s") is not None:
            line += f" (app CPU {d['app_cpu_s']}s over {d.get('wall_s', '?')}s wall: it was waiting, not working)"
        elif d.get("exception"):
            line += f" ({d['exception']})"
        out.append(line)
        if d.get("stack_hint"):
            verb = "crashed in" if r["kind"] == "crash" else "stuck in"
            out.append(f"  - {verb}: {' <- '.join(d['stack_hint'][:4])}")
    out.append("")

    out.append(f"## Live daemon check ({res['sample_seconds']}s sample each)")
    clean = []
    for r in res["daemons"]:
        bt = r.get("blocked_threads", [])
        if r.get("error"):
            out.append(f"- {r['name']} (pid {r['pid']}): {r['error']}")
            continue
        if not bt:
            clean.append(r["name"])
            continue
        flag = "**PILE-UP** " if r.get("pileups") else ""
        out.append(f"- {flag}**{r['name']}** (pid {r['pid']}, running {r['etime']}): "
                   f"{len(bt)} thread(s) blocked the whole window")
        for p in r.get("pileups", []):
            out.append(f"  - {p['clients']} XPC clients queued behind: {p['context']}")
            if p.get("head"):
                h = p["head"]
                out.append(f"  - likely head of the queue: request from {h['client']} (pid {h['client_pid']}), "
                           f"itself waiting on another process in: {h['waiting_in']}")
        for b in bt[:8]:
            who = f" [serving {b.get('client')} pid {b['client_pid']}]" if "client_pid" in b else ""
            out.append(f"  - {b['meaning']}{who}: {' > '.join(b['context'][-3:])}")
    if clean:
        out.append(f"- No long-blocked threads: {', '.join(sorted(set(clean)))}")
    if res.get("daemons_not_running"):
        out.append(f"- Not running right now (many start on demand, that is normal): {', '.join(res['daemons_not_running'])}")
    out.append("")

    if res.get("logs") is not None:
        out.append(f"## Sandbox mach-lookup denials (last {res['log_minutes']} min)")
        out.append("Some of these are normal background noise. Repeated ones from a process that is also blocked above are worth a look.")
        out += [f"- {l['process']} -> {l['service']}: {l['count']}" for l in res["logs"]] or ["- None."]
        out.append("")

    out += ["## Reading this",
            "- A watchdog kill with near-zero app CPU means the app was waiting on another process. Follow the wait.",
            "- A PILE-UP means one request inside that daemon never finished and everyone else queued behind it. It is the prime suspect.",
            "- One blocked thread can be momentary. Re-run before acting on a single finding.",
            "- This scan changed nothing. Any restart is a separate, deliberate step."]
    return "\n".join(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="Read-only scan for hangs and stuck system services on macOS.")
    ap.add_argument("--days", type=int, default=14, help="how far back to read crash/hang reports (default 14)")
    ap.add_argument("--seconds", type=int, default=2, help="sample length per process (default 2)")
    ap.add_argument("--pid", type=int, action="append", default=[], help="also sample this pid (e.g. a hung app)")
    ap.add_argument("--process", action="append", default=[], help="also sample processes with this name")
    ap.add_argument("--only-reports", action="store_true", help="skip live sampling")
    ap.add_argument("--log-minutes", type=int, default=0, help="also summarize sandbox denials from the last N minutes (slow)")
    ap.add_argument("--json", action="store_true", help="print JSON instead of Markdown")
    a = ap.parse_args()

    if sys.platform != "darwin":
        print("This scan only runs on macOS.", file=sys.stderr)
        return 2
    res = {"days": a.days, "sample_seconds": a.seconds, "log_minutes": a.log_minutes,
           "system": system_info(), "reports": scan_reports(a.days), "daemons": [], "logs": None}
    if not a.only_reports:
        res["daemons"], res["daemons_not_running"] = scan_daemons(DEFAULT_DAEMONS + a.process, a.pid, a.seconds)
    if a.log_minutes > 0:
        res["logs"] = scan_logs(a.log_minutes)
    print(json.dumps(res, indent=2, default=str) if a.json else render(res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
