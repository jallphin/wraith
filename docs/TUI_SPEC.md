# Wraith TUI — Implementation Spec

## Overview

The TUI has two modes:

1. **Capture mode** (`wraith`) — wraps the operator's shell in a pty, records all I/O silently. Minimal output: one status line on start, one on exit. Operator's terminal is unmodified.

2. **Review mode** (`wraith review [session-id]`) — full Bubbletea TUI for reviewing AI-proposed findings, editing narratives, approving/discarding, and exporting structured output.

---

## CLI Entry Points

Update `cmd/wraith/main.go` to support subcommands:

```
wraith                  # capture mode (wraps $SHELL)
wraith review           # review most recent session
wraith review <id>      # review specific session by ID
wraith list             # list all sessions (id, date, duration, event count, finding count)
```

---

## Data Models

### Severity

```go
type Severity int

const (
    SeverityInfo Severity = iota
    SeverityLow
    SeverityMedium
    SeverityHigh
    SeverityCritical
)

func (s Severity) String() string // "INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"
func (s Severity) Color() string  // lipgloss color: grey, blue, yellow, orange, red
```

### Phase

```go
type Phase string

const (
    PhaseRecon         Phase = "Reconnaissance"
    PhaseInitialAccess Phase = "Initial Access"
    PhaseExecution     Phase = "Execution"
    PhasePersistence   Phase = "Persistence"
    PhasePrivEsc       Phase = "Privilege Escalation"
    PhaseLatMov        Phase = "Lateral Movement"
    PhaseCollection    Phase = "Collection"
    PhaseExfil         Phase = "Exfiltration"
    PhaseImpact        Phase = "Impact"
    PhaseOther         Phase = "Other"
)
```

### FindingStatus

```go
type FindingStatus int

const (
    StatusProposed  FindingStatus = iota // AI-proposed, not yet reviewed
    StatusApproved                       // operator approved
    StatusDiscarded                      // operator discarded
)
```

### Finding

```go
type Finding struct {
    ID        string        // UUID
    SessionID string
    Title     string
    Severity  Severity
    Asset     string        // e.g. "DC01.corp.local (10.1.0.5)"
    Technique string        // e.g. "T1558.003 — Kerberoasting"
    Phase     Phase
    Narrative string        // operator-editable
    EventIDs  []int64       // references to events table in session DB
    Status    FindingStatus
    CreatedAt time.Time
    UpdatedAt time.Time
}
```

Findings are persisted to the session SQLite DB in a `findings` table. Schema:

```sql
CREATE TABLE IF NOT EXISTS findings (
    id         TEXT    PRIMARY KEY,
    session_id TEXT    NOT NULL,
    title      TEXT    NOT NULL,
    severity   INTEGER NOT NULL,
    asset      TEXT,
    technique  TEXT,
    phase      TEXT,
    narrative  TEXT,
    event_ids  TEXT,   -- JSON array of int64
    status     INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL
);
```

---

## TUI Layout

```
┌─────────────────────────────────────────────────────────────────┐
│  wraith review • session abc123 • 2h 14m • 847 events           │
├───────────────┬─────────────────────────────────────────────────┤
│ FINDINGS  6   │  [2/6]  CRITICAL — Kerberoast → Domain Admin    │
│               │                                                 │
│ ✓ CRIT  DC01  │  Asset:      DC01.corp.local (10.1.0.5)        │
│ ▶ CRIT  Kerb  │  Technique:  T1558.003 — Kerberoasting         │
│   HIGH  SMB   │  Phase:      Lateral Movement                   │
│   HIGH  RDP   │                                                 │
│   MED   Pass  │  Narrative:                                     │
│   LOW   Defs  │  ┌───────────────────────────────────────────┐  │
│               │  │ svc_backup held a weak password. The TGS  │  │
│               │  │ ticket cracked offline in <2 min, yielding │  │
│               │  │ full domain admin credentials.             │  │
│               │  └───────────────────────────────────────────┘  │
│               │                                                 │
│               │  Evidence: 14 events        [r] view raw        │
├───────────────┴─────────────────────────────────────────────────┤
│  [a]pprove  [e]dit  [d]iscard  [m]erge  [r]aw  [x]export  [?]  │
└─────────────────────────────────────────────────────────────────┘
```

**Left panel (25% width):** findings list. Scrollable. Color-coded by severity. Status icon: `✓` approved, `✗` discarded, `▶` selected, ` ` unreviewed.

**Right panel (75% width):** selected finding detail. Narrative is a scrollable viewport; pressing `e` switches it to a `textarea` for editing.

**Bottom bar:** key hints. Updates contextually (shows `[s]ave` when in edit mode).

**Header:** session metadata — ID (first 8 chars), duration, event count, finding counts (N approved / M total).

---

## Bubbletea Model

```go
type pane int

const (
    paneList     pane = iota
    paneDetail
    paneEvidence
)

type Model struct {
    // data
    session  *store.DB
    findings []Finding
    cursor   int    // index into findings

    // layout
    width  int
    height int
    focus  pane

    // components
    list      list.Model      // github.com/charmbracelet/bubbles/list
    narrative viewport.Model  // github.com/charmbracelet/bubbles/viewport
    editor    textarea.Model  // github.com/charmbracelet/bubbles/textarea
    evidence  viewport.Model

    // state flags
    editing      bool   // narrative textarea is active
    showEvidence bool   // evidence pane visible instead of detail
    showHelp     bool   // help overlay active

    // status
    statusMsg  string
    statusErr  bool
}
```

### Messages

```go
type windowSizeMsg struct{ width, height int }
type findingUpdatedMsg struct{ finding Finding }
type exportDoneMsg struct{ path string }
type errMsg struct{ err error }
```

---

## Key Bindings

### Normal mode (not editing)

| Key       | Action                                      |
|-----------|---------------------------------------------|
| `j` / `↓` | next finding                                |
| `k` / `↑` | prev finding                                |
| `Tab`     | cycle focus: list → detail → evidence       |
| `a`       | approve selected finding                    |
| `d`       | discard selected finding                    |
| `e`       | enter edit mode (narrative textarea)        |
| `m`       | merge selected with next finding            |
| `r`       | toggle raw evidence pane                    |
| `s`       | cycle severity (Info→Low→Med→High→Crit)     |
| `x`       | export all approved findings                |
| `?`       | toggle help overlay                         |
| `q`       | quit (confirm if unsaved changes)           |

### Edit mode (narrative textarea active)

| Key        | Action                    |
|------------|---------------------------|
| `Esc`      | exit edit mode (save)     |
| `Ctrl+S`   | save + exit edit mode     |
| All others | normal textarea input     |

---

## File Structure

```
internal/tui/
├── tui.go          — Model struct, Init(), Update(), View()
├── styles.go       — all lipgloss style definitions
├── keybinds.go     — key.Binding definitions (charmbracelet/bubbles/key)
├── finding.go      — Finding type, Severity, Phase, FindingStatus + methods
└── export.go       — export to JSON + Markdown

internal/synthesize/
└── synthesize.go   — reads event stream from DB, calls AI API, returns []Finding

store additions (internal/store/store.go):
- SaveFinding(f Finding) error
- LoadFindings(sessionID string) ([]Finding, error)
- UpdateFinding(f Finding) error
- ListSessions() ([]SessionMeta, error)
```

---

## Synthesis Flow

When `wraith review` is invoked:

1. Load session DB (most recent, or by ID)
2. Check `findings` table — if rows exist, load them and skip synthesis
3. If no findings: run `synthesize.Run(db)`:
   - Read all events from DB
   - Decode terminal output (strip ANSI escape codes)
   - Extract IP/hostname patterns, tool invocations, timestamps
   - Cluster events into candidate findings using heuristics:
     - Same target IP/hostname proximity
     - Known tool pattern signatures (nmap, msfconsole, mimikatz, bloodhound, etc.)
     - Temporal gaps >5min = likely phase boundary
   - Call AI API (configurable: Anthropic or OpenAI) with structured prompt
   - Parse response into `[]Finding`
   - Persist proposed findings to DB
4. Launch TUI with loaded findings

AI prompt approach: send clustered event summaries (not raw bytes — strip ANSI, truncate long outputs) to avoid token limits. Ask for structured JSON response matching the Finding schema.

---

## Export Format

`[x]` exports all `StatusApproved` findings.

**JSON** (`~/.wraith/sessions/<id>-findings.json`):
```json
{
  "session_id": "abc123",
  "exported_at": "2026-03-03T14:00:00Z",
  "findings": [
    {
      "id": "...",
      "title": "Kerberoast → Domain Admin",
      "severity": "CRITICAL",
      "asset": "DC01.corp.local (10.1.0.5)",
      "technique": "T1558.003",
      "phase": "Lateral Movement",
      "narrative": "..."
    }
  ]
}
```

**Markdown** (`~/.wraith/sessions/<id>-findings.md`):
```markdown
# Findings — Session abc123

## [CRITICAL] Kerberoast → Domain Admin

**Asset:** DC01.corp.local (10.1.0.5)
**Technique:** T1558.003 — Kerberoasting
**Phase:** Lateral Movement

svc_backup held a weak password...
```

---

## Dependencies to Add

```
github.com/charmbracelet/bubbles   — list, viewport, textarea, key components
github.com/google/uuid             — finding ID generation
```

`bubbletea` and `lipgloss` are already in go.mod.

---

## Implementation Notes

- **Do not break existing capture functionality** (`cmd/wraith/main.go`, `internal/capture/`, `internal/store/`)
- Add `findings` table migration to `store.NewSession()` — safe to add even if not yet used
- The `synthesize` package should be a no-op stub initially; actual AI call can be wired later
- All lipgloss styles in `styles.go` — nothing inline in `View()` functions
- Test with `wraith review` on a real session DB before considering done

---

## Out of Scope (this iteration)

- Web portal / API
- Multi-operator sessions
- C2 framework integration (Cobalt Strike, Metasploit log parsing)
- Voice note transcription
- Reporting portal UI
