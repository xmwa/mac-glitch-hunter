---
name: mac-glitch-hunter
description: Read-only diagnosis of macOS glitches. Use when a Mac app hangs, beachballs, won't open, keeps "crashing" at launch, or when several unrelated things misbehave at once (Messages won't open, Safari won't load sites until relaunched, iCloud or sign-in prompts stall), or when the user asks for a health scan of their Mac. Scans crash and hang reports, samples key per-user system daemons for long-blocked threads and XPC "pile-ups", then follows the chain of waiting processes down to the one that is actually stuck. Never kills or restarts anything without the user's explicit OK.
---

# mac-glitch-hunter

A hung Mac app is almost never broken by itself. It is waiting on another process, which is waiting on another, and somewhere at the bottom one request never got an answer. This skill finds that bottom process instead of restarting things at random.

## Hard rules

- **Read-only by default.** Scanning, sampling and reading logs change nothing. Killing or restarting any process is a separate step that needs the user's explicit OK, every time.
- **Never use `sudo`** unless the user asks. Everything here works on the user's own processes.
- **Use full paths:** `/usr/bin/sample` and `/usr/bin/log`. Homebrew can install a `sample` script that shadows Apple's, and zsh has a `log` builtin.
- **Don't trust the loudest log line.** Logs are noisy. The thread stacks are the evidence.

## Step 1. Run the scan

```bash
python3 <skill-dir>/scripts/glitch_scan.py                 # ~15 s
python3 <skill-dir>/scripts/glitch_scan.py --log-minutes 10  # also summarize sandbox denials (slower)
python3 <skill-dir>/scripts/glitch_scan.py --pid <PID>     # also sample a specific hung app
python3 <skill-dir>/scripts/glitch_scan.py --json          # machine-readable
```

(`uv run` works too; the script has no dependencies.) Start with the **Flags** section of the output.

The live check only samples processes owned by the current user. "No long-blocked threads" is therefore **inconclusive** if a hang's stack points at a root-owned service (`securityd`, `WindowServer`, the root `coreauthd`, `opendirectoryd`). In that case sample the hung app itself with `--pid`, read which service its blocked frames name, and if the bottom of the chain is root-owned, say so and recommend a logout or reboot rather than guessing.

What it does:

1. **System basics:** macOS version, uptime, memory free, swap, disk, top CPU.
2. **Crash and hang reports** from `~/Library/Logs/DiagnosticReports` and `/Library/Logs/DiagnosticReports`, grouped by process. It tells a watchdog kill (`0x8BADF00D`, a hang) from a real crash, shows app CPU time against wall time, and pulls the top of the stuck thread's stack.
3. **Live daemon check:** samples about 20 per-user system daemons that many apps depend on (`ctkd`, `coreauthd`, `identityservicesd`, `imagent`, `contactsd`, `accountsd`, `networkserviceproxy`, `cloudd` and others) and reports threads that sat in a blocking call for the whole window.
4. **Pile-up detection:** when several threads in one daemon serve different XPC clients and are stuck on the same code path, it reports who is queued and which request is probably at the head.

## Step 2. Read the evidence

**Crash reports**

| Signal | Meaning |
|---|---|
| `0x8BADF00D` + near-zero app CPU | Hang, not crash. The app waited on something for the whole watchdog window. Follow the wait. |
| `EXC_BAD_ACCESS`, `SIGABRT`, `SIGTRAP` | Real crash in that process. Its own stack is the place to look. |
| Reports that start on a specific day | Something happened then. Compare with daemon start times (`ps -o lstart= -p <pid>`). |

**Blocking calls in a sample**

| Frame | Meaning |
|---|---|
| `xpc_connection_send_message_with_reply_sync`, `__NSXPCCONNECTION_IS_WAITING_FOR_A_SYNCHRONOUS_REPLY__` | Waiting for another process to answer |
| `_dispatch_sync_f_slow`, `__DISPATCH_WAIT_FOR_QUEUE__` | Waiting for a queue another thread holds |
| `__ulock_wait`, `__psynch_mutexwait` | Waiting for a lock |
| `__semwait_signal` inside a loop | Sleeping and retrying something that keeps failing |

The frames just above the blocking call name the service on the other end.

## Step 3. Follow the wait (manual, when the scan points somewhere)

Repeat until you reach a process that is waiting on something that will never answer.

1. **Reproduce the hang if needed and sample the app:** `/usr/bin/sample <pid> 3 -file /tmp/x.txt`, or run the scan with `--pid`.
2. **Identify the peer** from the blocked thread:
   - Framework names in the stack: `IDS` → `identityservicesd`, `IMCore` → `imagent`, `Contacts`/`CNContactStore` → `contactsd`, `TKRemoteSEPKey`/`SecKeyCreateSignature` → `ctkd`, `LAClient`/`LAContext` → `coreauthd`, `CloudKit` → `cloudd`, `Accounts`/`ACAccountStore` → `accountsd`.
   - **Server-side queue names.** In a daemon's sample, threads serving a client often run on queues like `com.apple.NSXPCConnection.user.anonymous.<pid>`. That number is the client's PID, so one sample of a server shows everyone waiting on it.
   - `ps -Ao pid,user,etime,comm` to see how long each candidate has been running.
3. **Sample the peer** and repeat.
4. **Check the blast radius.** Everything else queued behind the culprit is broken too, even if it looks unrelated. Map client PIDs to names with `ps -p <pid> -o comm=`.
5. **Test your suspect.** If restarting a process doesn't help and the fresh copy gets stuck at the same spot within seconds, the real problem is further down. Keep going.

## Step 4. Propose a fix and ask

Only after the chain is clear. A process is a reasonable restart candidate when **all** of these hold:

- It runs as the current user: `ps -o user= -p <pid>`.
- launchd relaunches it on demand: `launchctl print user/$(id -u)/<label>` or `gui/$(id -u)/<label>` shows it, or it is a known on-demand agent.
- It is at the **bottom** of the chain. Restart bottom first, then the layers above, so they reconnect to a fresh copy.

Explain the side effects in plain words (for example, "iMessage and FaceTime will drop for a few seconds"), give the exact command, and wait for the user's OK. Plain `killall` sometimes doesn't take on a wedged daemon; `killall -9 <name>` is the usual next step for a per-user, on-demand service. Never touch root-owned daemons without the user explicitly asking. If the chain ends somewhere you can't safely restart, recommend a logout or reboot and say why.

## Step 5. Verify with the same tool

Sample the restarted daemon again and confirm the blocked threads are gone, then confirm the user's symptom is actually fixed (the app opens, the site loads). Report what was verified and what is only expected.

## Worked example

Messages hung at launch (watchdog kill, 0.7 s CPU over 20 minutes) and Safari sometimes couldn't load sites. The chain was Messages → `imagent` → `identityservicesd` → `ctkd`. In `ctkd`, one signing request was waiting on LocalAuthentication forever while holding a lock, and requests from `networkserviceproxy` (Safari's proxy), `transparencyd`, `iCloudNotificationAgent` and a fresh `identityservicesd` were queued behind it. Loud Contacts sandbox errors in `imagent` turned out to be a side effect. Restarting `imagent` and `identityservicesd` did nothing; restarting the user's `ctkd` (then the layers above) fixed both apps without a reboot:

```bash
killall -9 ctkd; sleep 3; killall -9 identityservicesd imagent
```

The scan reports this case as a **PILE-UP in ctkd** with the head request coming from `identityservicesd`.
