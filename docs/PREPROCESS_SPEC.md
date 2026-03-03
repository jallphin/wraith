# Wraith — Preprocessing & AI Synthesis Spec

## Goal

Replace the mock stub in `internal/synthesize/synthesize.go` with a real pipeline:
1. Load session events from SQLite
2. Preprocess terminal I/O → structured `(command, output)` pairs
3. Cluster pairs into phases
4. Build AI prompt, call model API, parse response into `[]store.Finding`

---

## Files to Create/Modify

```
internal/synthesize/
├── synthesize.go     — REPLACE stub: orchestrate the full pipeline
├── preprocess.go     — NEW: parse output stream → CommandPair list
├── cluster.go        — NEW: group CommandPairs into Phase clusters
└── prompt.go         — NEW: build prompt + call AI API + parse response
```

---

## 1. preprocess.go

### Types

```go
type CommandPair struct {
    Command   string    // the command the operator typed
    Output    string    // terminal output that followed
    Timestamp time.Time // timestamp of the command
    Targets   []string  // extracted IPs/hostnames mentioned in output
}
```

### LoadEvents

Read all events from the session DB:
```go
func LoadEvents(db *store.DB) ([]store.Event, error)
```
Use: `SELECT kind, ts, data FROM events ORDER BY ts`

### StripANSI

Strip ANSI escape sequences from terminal output bytes:
```go
func StripANSI(b []byte) string
```
Regex: `\x1b\[[0-9;]*[mGKHFABCDsuJr]` and `\x1b\][^\x07]*\x07` and other common sequences.

### ExtractCommandPairs

Parse the output stream to extract command/output pairs:
```go
func ExtractCommandPairs(events []store.Event) []CommandPair
```

**Algorithm:**
- Focus on `EventOutput` events only (the output stream contains echoed commands + results)
- Concatenate all output bytes, strip ANSI
- Split on common shell prompt patterns:
  - `$ ` (bash/sh)
  - `# ` (root)
  - `❯ ` (zsh/oh-my-zsh)
  - `> ` (generic)
  - Pattern: line ending with one of these suffixes, followed by a newline
- For each segment between prompts: first line = command, rest = output
- Skip empty commands or pure whitespace
- Extract IPs/hostnames from output using regex:
  - IPv4: `\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`
  - Hostnames: words matching `[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+`
- Timestamps: use the timestamp of the output event closest to the segment start

### TruncateOutput

Cap long outputs to avoid token bloat:
```go
func TruncateOutput(output string, maxLines int) string
```
- If output > maxLines (default 50): keep first 20 lines + `\n[... N lines truncated ...]` + last 5 lines
- For nmap-style output, detect and summarize: if output contains "Nmap scan report" extract port list instead of full output

---

## 2. cluster.go

### Phase

```go
type Phase struct {
    Label    string        // "Phase 1", "Recon", etc. — AI assigns final label
    Pairs    []CommandPair
    Start    time.Time
    End      time.Time
    Targets  []string      // deduplicated targets across all pairs
}
```

### ClusterPairs

Group CommandPairs into phases:
```go
func ClusterPairs(pairs []CommandPair, gapThreshold time.Duration) []Phase
```

**Algorithm:**
- Default gap threshold: 5 minutes
- Start new phase when:
  - Time gap between consecutive commands > gapThreshold
  - OR command targets a new subnet/host not seen in current phase (optional, best-effort)
- Assign sequential labels: "Phase 1", "Phase 2", etc.
- Deduplicate targets per phase

---

## 3. prompt.go

### Config

Read from environment (in priority order):
1. `ANTHROPIC_API_KEY` → use Anthropic API (`claude-sonnet-4-5`)
2. `OPENAI_API_KEY` → use OpenAI API (`gpt-4.1`)
3. Neither → return error "no AI API key configured"

### BuildPrompt

```go
func BuildPrompt(phases []Phase, sessionID string) string
```

Build a prompt like:
```
You are analyzing a red team engagement session. The operator's commands and outputs
are grouped into phases below. Identify security findings.

Return a JSON array of findings matching this exact schema:
[{
  "title": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "asset": "string (hostname/IP or description)",
  "technique": "string (MITRE ATT&CK ID and name if applicable)",
  "phase": "string (Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Lateral Movement|Collection|Exfiltration|Impact|Other)",
  "narrative": "string (2-4 sentences describing the finding)"
}]

Only include genuine security findings. If nothing notable, return [].

Session ID: <sessionID>

--- Phase 1 (14:00 - 14:23) ---
Targets: 10.1.0.0/24

$ nmap -sV 10.1.0.0/24
[truncated output summary]

$ msfconsole
[truncated]

--- Phase 2 (14:35 - 14:52) ---
...
```

### CallAI

```go
func CallAI(prompt string) (string, error)
```

Make HTTP POST to the configured provider:

**Anthropic:**
```
POST https://api.anthropic.com/v1/messages
Headers: x-api-key, anthropic-version: 2023-06-01, content-type: application/json
Body: {"model": "claude-sonnet-4-5", "max_tokens": 2048, "messages": [{"role": "user", "content": prompt}]}
```

**OpenAI:**
```
POST https://api.openai.com/v1/chat/completions
Headers: Authorization: Bearer <key>, Content-Type: application/json
Body: {"model": "gpt-4.1", "messages": [{"role": "user", "content": prompt}], "max_tokens": 2048}
```

### ParseFindings

```go
func ParseFindings(response string, sessionID string) ([]store.Finding, error)
```

- Extract JSON array from response (model may wrap it in prose or markdown code fences)
- Unmarshal into intermediate struct, map to `[]store.Finding`
- Set `Status: store.StatusProposed`, `CreatedAt/UpdatedAt: time.Now()`
- Generate UUIDs for IDs

---

## 4. synthesize.go (updated)

Replace stub with:

```go
func Run(db *store.DB) ([]store.Finding, error) {
    events, err := LoadEvents(db)
    pairs := ExtractCommandPairs(events)
    if len(pairs) == 0 {
        // no commands captured — return empty (TUI handles this gracefully)
        return nil, nil
    }
    phases := ClusterPairs(pairs, 5*time.Minute)
    prompt := BuildPrompt(phases, db.SessionID)
    response, err := CallAI(prompt)
    findings, err := ParseFindings(response, db.SessionID)
    // Save findings to DB
    for i := range findings {
        db.SaveFinding(findings[i])
    }
    return findings, nil
}
```

---

## Build Constraints

- Go binary at: `~/.local/go/bin/go`
- Use only stdlib for HTTP (no extra HTTP client deps needed)
- `go build ./...` must pass with zero errors
- Do NOT change any existing files outside `internal/synthesize/`
- Commit message: `feat: implement preprocessing + AI synthesis pipeline`
- Push to origin (git remote already has auth token embedded)
