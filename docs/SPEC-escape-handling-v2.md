# Wraith — Input Reconstruction v2 Spec
## Robust Escape Sequence Handling + TUI Mode Detection

_Status: SPEC — ready for implementation_  
_Scope: `internal/synthesize/preprocess.go`_

---

## Problem Statement

The current escape sequence parser in `ExtractCommandPairs` is an **opt-in recognizer** — it handles known sequences and silently leaks unrecognized bytes into the line editor buffer. This causes command garbling whenever the terminal emits sequences the parser doesn't know about (e.g., OSC variants, Konsole shell integration, application-specific sequences).

The OSC ST terminator bug (`ESC \` vs BEL) was the most recent example. There will be more.

---

## Design Goals

1. **Strict-discard escape consumer** — any byte inside an escape sequence is consumed and never reaches the line editor, whether recognized or not.
2. **Correct reconstruction for normal shell use** — bash/zsh/fish readline commands reconstruct cleanly.
3. **Correct reconstruction for readline-based TUIs** — msfconsole, sliver, sqlmap interactive, python REPL all use readline; same `\r`-boundary logic applies.
4. **TUI mode detection** — detect alternate-screen entry/exit from the output stream; tag TUI blocks for context without attempting keystroke-level reconstruction inside them.
5. **No regressions** — existing cursor movement (arrows, Home/End, Ctrl ops) must continue to work.

---

## Escape Sequence Taxonomy

Terminal escape sequences follow well-defined grammar. The consumer must handle all categories:

### 1. C0 Control Codes (single byte, 0x00–0x1F)
Handled directly in the main switch. Not escape sequences. Keep as-is.

### 2. ESC + single byte (Fe sequences, 0x40–0x5F)
Examples: `ESC =` (application keypad), `ESC >` (normal keypad), `ESC 7` (save cursor), `ESC 8` (restore cursor)
**Action:** consume the single byte after ESC, discard both.

### 3. CSI — Control Sequence Introducer (`ESC [`)
Followed by: zero or more parameter bytes (0x30–0x3F), zero or more intermediate bytes (0x20–0x2F), one final byte (0x40–0x7E).
**Action:** consume all parameter + intermediate + final bytes. Act on recognized sequences (arrow keys, Delete, Home, End). Discard all others.

Recognized CSI sequences to keep acting on:
- `ESC[D` — cursor left (arrow left)
- `ESC[C` — cursor right (arrow right)  
- `ESC[A` — cursor up (history — currently ignored, keep ignoring)
- `ESC[B` — cursor down (currently ignored, keep ignoring)
- `ESC[H` — Home
- `ESC[F` — End
- `ESC[3~` — Delete key (forward delete)
- `ESC[1~`, `ESC[7~` — Home variants
- `ESC[4~`, `ESC[8~` — End variants
- `ESC[1;5C` — Ctrl+Right (word forward)
- `ESC[1;5D` — Ctrl+Left (word backward) ← **ADD THIS** (currently missing)

### 4. OSC — Operating System Command (`ESC ]`)
Followed by: arbitrary bytes until BEL (0x07) **or** ST (`ESC \`).
ST = `ESC` followed by `\` (0x5C) — this is the current bug source.
**Action:** consume all bytes including the terminator. Never emit anything. No exceptions.

Current fix (`cf57c55`) handles this correctly via state 5. ✅

### 5. SS3 — Single Shift 3 (`ESC O`)
Followed by exactly one byte.
Examples: `ESC O A/B/C/D` (arrow keys on some terminals), `ESC O H/F` (Home/End), `ESC O P/Q/R/S` (F1–F4)
**Action:** consume the one byte. Act on cursor movement variants. Discard F-keys and unknown.

### 6. DCS — Device Control String (`ESC P`)
Followed by arbitrary bytes until ST (`ESC \`).
**Action:** consume everything until ST, same as OSC.

### 7. APC — Application Program Command (`ESC _`)
Followed by arbitrary bytes until ST.
**Action:** consume until ST, discard.

### 8. PM — Privacy Message (`ESC ^`)
Followed by arbitrary bytes until ST.  
**Action:** consume until ST, discard.

### 9. SOS — Start of String (`ESC X`)
Followed by arbitrary bytes until ST.
**Action:** consume until ST, discard.

---

## State Machine Redesign

Replace the current `escState` int + `csiParam` slice with a clean named-state enum:

```go
type escMode int
const (
    escNone   escMode = iota
    escEsc             // saw ESC, deciding type
    escCSI             // in CSI (ESC [), accumulating params
    escOSC             // in OSC (ESC ]), consuming until BEL or ST
    escSS3             // in SS3 (ESC O), next byte is the final
    escDCS             // in DCS/APC/PM/SOS, consuming until ST
    escST              // saw ESC inside a string sequence, expect \
    escFe              // single-byte Fe sequence, consuming one byte
)
```

### Transition Table

| Current state | Byte | Next state | Action |
|---|---|---|---|
| `escNone` | `0x1B` | `escEsc` | — |
| `escEsc` | `[` | `escCSI` | clear param buf |
| `escEsc` | `]` | `escOSC` | — |
| `escEsc` | `O` | `escSS3` | — |
| `escEsc` | `P`,`_`,`^`,`X` | `escDCS` | — |
| `escEsc` | `0x40`–`0x5F` (other Fe) | `escFe` | — |
| `escEsc` | `0x1B` | `escEsc` | stay (ESC ESC = meta prefix) |
| `escEsc` | anything else | `escNone` | discard |
| `escCSI` | `0x30`–`0x3F` | `escCSI` | accumulate param |
| `escCSI` | `0x20`–`0x2F` | `escCSI` | accumulate intermediate |
| `escCSI` | `0x40`–`0x7E` | `escNone` | **dispatch** recognized sequences, discard rest |
| `escOSC` | `0x07` | `escNone` | BEL terminator, discard |
| `escOSC` | `0x1B` | `escST` | possible ST start |
| `escOSC` | anything else | `escOSC` | consume |
| `escDCS` | `0x1B` | `escST` | possible ST start |
| `escDCS` | anything else | `escDCS` | consume |
| `escST` | `\` (0x5C) | `escNone` | ST complete, discard |
| `escST` | `0x1B` | `escST` | stay (another ESC) |
| `escST` | anything else | `escNone` | malformed ST, discard byte and exit |
| `escSS3` | any | `escNone` | **dispatch** H/F/A/B/C/D, discard rest |
| `escFe` | any | `escNone` | discard (single-byte Fe consumed) |

**Key property:** In every state other than `escNone`, bytes are consumed and never reach `edInsert()`. There is no path from any escape state to the line editor except through `escNone`.

---

## TUI Mode Detection (Output Side)

Scan output events for alternate-screen sequences:

```
ESC[?1049h  — enter alternate screen (TUI started: vim, nano, msfconsole, htop...)
ESC[?1047h  — alternate form
ESC[?47h    — old alternate form
ESC[?1049l  — exit alternate screen (TUI ended)
```

Add to `ExtractCommandPairs` (or a pre-pass):

```go
type tuiWindow struct {
    start time.Time
    end   time.Time  // zero if still active
    cmd   string     // the shell command that launched it (e.g. "nano /etc/hosts")
}
```

During output processing, detect these sequences and record TUI windows. When building `CommandPair` output, if a command's output window overlaps a TUI window, tag the pair:

```go
pair.TUIMode = true
pair.TUILabel = "nano"  // extracted from the launch command
```

The AI prompt can then handle these differently — e.g., "operator used nano to edit /etc/hosts" rather than trying to interpret the raw keystroke reconstruction.

---

## New Features (add while we're here)

### Ctrl+Left (word backward) — currently missing
CSI sequence: `ESC[1;5D`
Action: skip word backward (mirror of existing `ESC[1;5C` word forward)

```go
case "1;5D": // Ctrl+Left — skip word backward
    for ed.pos > 0 && ed.buf[ed.pos-1] == ' ' {
        ed.pos--
    }
    for ed.pos > 0 && ed.buf[ed.pos-1] != ' ' {
        ed.pos--
    }
```

### Alt+B / Alt+F (word move via ESC b/f)
Some readline configs emit `ESC b` and `ESC f` for word movement.
Currently these hit `escFe` and get discarded (correct for unknown Fe), but `b` and `f` are 0x62/0x66 which are NOT in the Fe range (0x40–0x5F). They'll fall through to `escNone` and get inserted. Need explicit handling in `escEsc` state:

```go
case 'b': // Alt+B — word backward
    // same as Ctrl+Left word backward
case 'f': // Alt+F — word forward  
    // same as Ctrl+Right word forward
```

---

## Implementation Notes

- The `csiParam` slice should be `[]byte`, cleared on CSI entry. Keep as-is.
- The state machine is in `ExtractCommandPairs` only — `capture.go` stores raw bytes unchanged.
- TUI detection requires a pre-pass over output events to build the `[]tuiWindow` slice before command pair construction.
- No changes to `store`, `capture`, or `tui` packages.
- `wraith resyn` on the expressway session should be tested after implementation to validate command reconstruction quality.

---

## Test Cases (verify after implementation)

1. **Normal shell commands** — `ping expressway.htb`, `sudo nmap -sS`, `ssh ike@expressway.htb` → reconstruct correctly
2. **OSC shell integration** — Konsole `]8003;...ESC\` sequences → silently consumed, no garbling
3. **Password entry** — `sudo` password prompt → input consumed, not reconstructed as a command
4. **nano session** — `nano /etc/hosts` → TUI window tagged, arrow key spam inside nano consumed cleanly
5. **msfconsole** — `use exploit/linux/local/sudo_baron_samedit`, `set RHOSTS 10.10.10.1`, `run` → reconstructed as normal readline commands
6. **Ctrl+Left/Right** — word navigation → cursor moves correctly, final command correct
7. **Unknown escape sequences** — e.g., `ESC[?2004h` (bracketed paste mode) → fully consumed, no bytes leaked

---

## Files Changed

- `internal/synthesize/preprocess.go` — all changes contained here
  - Replace `escState int` + `csiParam` with new state machine
  - Add TUI window detection pre-pass
  - Add `TUIMode bool` + `TUILabel string` fields to `CommandPair`
- `internal/synthesize/prompt.go` — update prompt builder to handle `TUIMode` pairs differently

---

_End of spec._
