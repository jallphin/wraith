# wraith

Passive shell session capture for red team engagements.

Wraith wraps your shell in a transparent pty layer, recording all I/O to a local
SQLite database — no prefixes, no hotkeys, no breaking flow. When the engagement
is done, the session log feeds an AI synthesis pipeline that clusters activity by
target and phase, then proposes structured findings for operator review.

## How it works

```
operator runs wraith
  → pty wrapper captures all stdin/stdout silently
  → every event timestamped + stored in ~/.wraith/sessions/<id>.db
  → end of session: AI reads event stream, proposes finding buckets
  → operator reviews/approves in TUI
  → structured findings exported for reporting portal
```

## Architecture

```
wraith/
├── cmd/wraith/         — entry point, shell wrapper
├── internal/capture/   — pty interception layer
├── internal/store/     — SQLite event store
└── internal/tui/       — Bubbletea session review (WIP)
```

## Install

```bash
go install github.com/jallphin/wraith/cmd/wraith@latest
```

## Usage

```bash
# Start a captured session (wraps your default shell)
wraith

# All commands run normally — wraith is invisible
nmap -sV 10.0.0.0/24
msfconsole
...

# Exit shell to end session
exit
# Session saved to ~/.wraith/sessions/<timestamp>.db
```

## Status

Early development. Core pty capture + event store in progress.

---

Part of the Cathedral Cyber toolchain.
