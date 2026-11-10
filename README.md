# mac-glitch-hunter

An agent skill for finding out why a Mac app hangs, beachballs or refuses to open, without rebooting.

Most "crashes" at launch aren't crashes. The app sits waiting on a system service, that service waits on another, and somewhere down the chain one request never gets an answer. Restarting the app or the Mac hides that. This skill follows the chain of waiting processes down to the one that is actually stuck, and it never kills or restarts anything without asking.

## What it does

`scripts/glitch_scan.py` is a read-only scanner (Python standard library, no dependencies, about 15 seconds):

- **Crash and hang reports.** Groups everything in `DiagnosticReports` by process and tells a watchdog hang (`0x8BADF00D`, near-zero CPU) from a real crash.
- **Live daemon check.** Samples about 20 per-user system daemons (`ctkd`, `coreauthd`, `identityservicesd`, `imagent`, `contactsd`, `accountsd`, `networkserviceproxy`, `cloudd` and more) and flags threads that stayed in a blocking call for the whole sample.
- **Pile-up detection.** When several apps' requests are queued inside one daemon behind a single stuck request, it names the daemon, who's queued and the request at the head. One wedged daemon can break apps that look unrelated, so this is usually the culprit.
- **System basics.** Memory, swap, disk and top CPU, plus optional sandbox-denial counts from the unified log.

`SKILL.md` teaches the agent how to read the output and follow the wait by hand: sample, identify the peer, sample the peer, check the blast radius, then propose the smallest safe restart and verify it.

## How it differs from other Mac troubleshooting skills

Most of those look at resource usage or read crash logs one app at a time. This one traces a hang **across processes**, using `sample` and the client PIDs in XPC queue names, to find the service everything is waiting on.

## Install

With the [skills CLI](https://skills.sh):

```bash
npx skills add xmwa/mac-glitch-hunter
```

As a Claude Code plugin:

```
/plugin marketplace add xmwa/mac-glitch-hunter
/plugin install mac-glitch-hunter@mac-glitch-hunter
```

Or copy `skills/mac-glitch-hunter` into `~/.claude/skills/`.

Then ask your agent something like "Messages won't open, find out why" or "scan my Mac for glitches".

## Run the scanner directly

```bash
python3 skills/mac-glitch-hunter/scripts/glitch_scan.py               # Markdown report
python3 skills/mac-glitch-hunter/scripts/glitch_scan.py --log-minutes 10
python3 skills/mac-glitch-hunter/scripts/glitch_scan.py --pid 1234    # also sample a hung app
python3 skills/mac-glitch-hunter/scripts/glitch_scan.py --json
```

Requires macOS. It only samples processes owned by the current user, so it never needs `sudo`.

## Background

The method comes from a real case: Messages hung at launch and Safari intermittently failed to load pages. Both traced back to one deadlocked CryptoTokenKit daemon (`ctkd`), fixed without a reboot. The write-up: [Chasing Glitches: From Crash Report to Root Cause on macOS](https://blog.wangxm.com/2026/11/chasing-glitches-from-crash-report-to-root-cause-on-macos/).

## License

MIT
