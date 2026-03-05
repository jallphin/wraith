# Wraith v3 — Dual-Stream Command Extraction

## 1. Core Design: Output-Echo as Primary Source

Wraith already sees the clean, post-edit text stream that the shell prints back before running a command. Every command submitted via Enter is echoed verbatim to the **output stream** (`stdout`/`stderr`) because shells echo the final buffer after editing is done and before execution begins. This echo is the final, canonical command string — aliases expanded, prompts stripped, line continuations resolved. It is not a reconstruction of raw keystrokes; it is the shell telling us what it will execute.

By making the output stream the primary source for command extraction, we remove the need to emulate a line editor or guess at escape sequences. The existing input-based state machine becomes a secondary signal: a rich source of timestamps, metadata (Enter, special keys, paste bursts), and a validation/fallback channel. Output echo is stable across shells and terminal emulators because it reflects what the shell actually executes, not how the terminal renders it.

This is more reliable than parsing the input stream because:

1. **No escape parsing** — we already get the cleaned-up string; ANSI sequences from keystrokes never reach us.
2. **No line-buffer reconstruction** — the shell does that work for us. We only need to detect chunk boundaries.
3. **Less fragile to unusual typing** — paste bursts, arrow keys, and backspace edits already happened in the shell.

Keep the input extractor running as a safety net, but let output echo drive the canonical `command_text` we log.

## 2. Output-Side Command Extraction

### Prompt Boundary Detection

**Flow:** strip ANSI → detect prompt → capture everything after the prompt until the next carriage return/line-feed pair that signifies the shell is about to execute.

1. **ANSI stripping:** run every output buffer through a fast ANSI stripper (reuse existing helper) before pattern matching. Prompts often include colors and hyperlinks.
2. **Prompt patterns:** maintain a prioritized list of regex patterns that match the portion of the output that precedes the user command. Example patterns:
   - `(?:sudo )?[\w@\-\.]+[\w\-]*[#$%]\s` (standard `sh`/`bash`/`dash`) → `$ `, `# `, `% `
   - `┌──\(.*?\)-\[[^\]]+\]\n└─[#$] ` → Kali multi-line prompts (root@kali)
   - `\[[^\]]+\]\s?[^\n]+@[^\n]+:\S+\s` → custom PS1 with git/venv info
   - `msf6(?:\s+\w+\([^\)]*\))?\s> ` → msfconsole prompt variations
   - `\[[^\]]+]\s+sliver(?:\s+\(SESSION\))?\s> ` → Sliver C2 console
   - `>>> ` and `\.\.\. ` → Python/REPL prompts; treat these as prompt + command, remembering that `...` indicates continuation

Keep a fallback `promptRegex` if none of the preset patterns match, e.g. detect `^(?:[^\r\n]+[#$%]\s)$` near line starts.

### Command Echo Extraction

After detecting a prompt boundary:

1. Capture everything between the prompt match and the next `\r\n` (or the stream boundary if output is incomplete).
2. Trim trailing whitespace because shells echo with a newline; the command should not include it.
3. Normalize multi-line commands:
   - If a line ends with `\` (bash continuation), treat the literal multi-line echo as a single command by removing the `\` and concatenating the next prompt-less segment.
   - If heredoc syntax is used (`<<'EOF'`), continue collecting lines until the closing identifier appears and `\r\n` indicates the shell prompt has returned.

Example pseudo flow:

```go
func extractFromOutput(output []byte) ([]CommandPair, error) {
    clean := stripANSI(output)
    lines := bytes.Split(clean, []byte("\r\n"))
    for _, line := range lines {
        if prompt := matchPrompt(line); prompt != nil {
            cmdText := bytes.TrimSpace(line[len(prompt):])
            if isContinuation(line) {
                cmdText = joinContinuation(cmdText, nextLine)
            }
            commands = append(commands, CommandPair{Command: string(cmdText), Source: "output"})
        }
    }
    return commands, nil
}
```

### Edge Cases

- **Multi-line commands:** when the shell prints the command across multiple lines (e.g., `echo foo \
    bar`), the output echo includes the literal continuation markers. Detect trailing `\` and accumulate subsequent lines until a prompt is emitted again.
- **Heredocs:** monitor for `<<EOF` sequences in the captured command and treat the heredoc body as part of the command until the closing identifier appears before the next prompt.
- **REPLs:** some prompts (`>>>`, `...`) need context to know when input is complete. Use heuristics: `>>>` always starts a new command, while `...` is continuation. Only emit when `>>>` or `msf6` prompt returns.
- **Remote SSH sessions:** output is proxied from the remote shell but still contains the prompt and command echo. The logic is identical, but timestamps/metadata originate from the local PTY.

## 3. Input Stream as Enricher/Validator

### Timestamp Correlation

Match each output-derived command boundary with the Enter keypress timestamp from the input stream. Keep the Enter byte indices so we can say “command executed at T.” Use a sliding window around each output command: find the nearest `\r`/`\n` keypress in the input log within a small delta (e.g., 50ms of the output prompt boundary) and associate the timestamp.

### Paste Detection

Use timing between input bytes to detect bursts:

- **Paste**: >8 bytes in <10ms → treat as paste; flag the resulting command with `Paste=true`.
- **Typed**: bytes spaced ≥10ms/byte.

Pastes help identify commands that contain multi-line payloads (e.g., heredocs) even if the user never hit Enter manually. Use this metadata to annotate the `command pair` record.

### Fallback Mode

If the output extractor fails (no prompt match, the shell has `stty -echo`, the session is blind-injection, or the shell never echoes commands), fall back to the existing v2 input reconstruction. Keep the input extractor running in parallel and use its result whenever the output stream yields nothing. This ensures older sessions keep working.

### Validation

When both output and input reconstructions exist and disagree, treat the output echo as authoritative. Log the discrepancy (command IDs, timestamps, sample diff) and continue. Input results can still flag anomalies, but the output string is what gets synthesized into findings.

## 4. Multi-Terminal / Multiple Sessions

- **Current behavior:** each `wraith` run wraps a single PTY. To cover multiple terminal windows, the operator runs multiple `wraith` instances, resulting in multiple SQLite DBs per engagement.
- **Merge plan:** `wraith-report` will merge per-session DBs using the engagement ID (`[engagement.id]` in `config.toml`) as the join key. Keep per-PTY metadata (session UUID, machine) to disambiguate.
- **Operator discipline:** remind operators to run wraith in every active window/pane they care about; the tool cannot magically see other PTYs.
- **Metadata:** tag each session record with the engagement ID, `session_uuid`, and `tty` path to aid downstream merging.

## 5. tmux/screen Integration (Future Direction)

### Problem
Wraith inside tmux/screen only sees the output from the active pane. Background panes do not emit data to the wrapped PTY, so commands executed elsewhere are invisible.

### Option A — Pragmatic (Today’s recommendation)
Run `wraith` *outside* of tmux. The terminal running wraith should start tmux inside it. Wraith captures everything tmux renders, including pane switches and commands from multiple panes that have been drawn to the screen. This works now and is the easiest path forward.

### Option B — Future proper support via `tmux pipe-pane`
Build a tmux integration where each pane feeds an independent capture stream:

1. `tmux pipe-pane -o -t SESSION:WINDOW.PANE 'cat >> /path/to/pane-output.log'` for each pane.
2. Treat each pane log as its own wraith session (per-pane DBs). Use timestamps and engagement ID to merge them later.
3. Hook `tmux`’s `command-hook` to detect command boundaries within each pane, giving us accurate start/end points without relying on prompt detection alone.
4. The final synthesis stage merges the per-pane command feeds using aligned timestamps and the engagement ID.

Option B delivers true multi-pane awareness. Treat Option A as the near-term recommendation and Option B as the long-term goal.

## 6. Known Limitations

- **GUI tools (Burp, Covenant, browsers):** they don’t emit textual command echoes. Use `wraith note` to annotate GUI interactions manually.
- **`stty -echo` sessions:** output echo vanishes; rely on input reconstruction until wraith detects echo’s return.
- **Clipboard copy/paste from terminal output:** wraith never sees clipboard actions, so commands pasted via GUI clipboard aren’t captured unless the keystrokes enter the shell via input stream.
- **Nested wraith (wraith inside wraith):** creates recursive wrapping and confusing timestamps. Avoid chaining wraith processes.

## 7. Implementation Path

1. Introduce `extractFromOutput()` in `preprocess.go`. This ~150-line function:
   - strips ANSI, runs prompt matchers, and emits `CommandPair{Command: string, Source: "output", Prompt: promptName}`.
   - handles continuations and heredocs.
2. Update `ExtractCommandPairs` (v2) to call the output extractor first:
   - if `extractFromOutput()` returns commands, mark them as `source=output`; enrich them with input metadata (timestamps/paste flag) by correlating with `inputEvents`.
   - if it returns nothing, fall back to the existing input-based extraction and mark those commands `source=input`.
3. Keep both extractors running so zero regression risk exists for old sessions.
4. Log any disagreements between output and input to aid debugging.

### Example structural change

```go
func ExtractCommandPairs(ctx context.Context, inputEvents []InputEvent, outputBuf []byte) ([]CommandPair, error) {
    if cmds := extractFromOutput(outputBuf); len(cmds) > 0 {
        return enrichWithInput(ctx, cmds, inputEvents)
    }
    return extractFromInput(inputEvents)
}
```

5. Estimated effort: one new helper (~150 lines), a small gate in `ExtractCommandPairs`, updated logging/metadata. Keep the existing input path untouched for fallback.

## Files Changed

- `docs/SPEC-command-extraction-v3.md` (new spec)
- `preprocess.go` (add `extractFromOutput`, continue to support fallback)
- `extractor.go` / existing input helpers (update `ExtractCommandPairs` to orchestrate output-first workflow)
