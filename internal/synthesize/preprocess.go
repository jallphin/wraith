package synthesize

import (
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"time"
	"unsafe"

	"github.com/jallphin/wraith/internal/store"
)

const defaultMaxOutputLines = 50
const promptLookbackLimit = 80

var (
	ansiRegex     = regexp.MustCompile(`\x1b\[[0-9;]*[A-Za-z]|\x1b\][^\x07]*\x07|\x1b[@-_][0-?]*[ -/]*[@-~]`)
	ipv4Regex     = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	hostnameRegex = regexp.MustCompile(`\b[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(?:\.[a-zA-Z]{2,})+\b`)
	promptMarkers = []string{"$ ", "# ", "❯ ", "> "}
)

type CommandPair struct {
	Index     int
	Command   string
	Output    string
	Timestamp time.Time
	Targets   []string
	TUIMode   bool   // true if this command launched a full-screen TUI (vim, nano, etc.)
	TUILabel  string // name of the TUI process, e.g. "nano"
}

// tuiWindow records a period when the terminal was in alternate-screen mode.
type tuiWindow struct {
	start time.Time
	end   time.Time // zero if still active at session end
}

func LoadEvents(db *store.DB) ([]store.Event, error) {
	conn, err := getDBConn(db)
	if err != nil {
		return nil, err
	}

	rows, err := conn.Query(`SELECT kind, ts, data, note FROM events ORDER BY ts`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []store.Event
	for rows.Next() {
		var kind string
		var ts int64
		var data []byte
		var note sql.NullString
		if err := rows.Scan(&kind, &ts, &data, &note); err != nil {
			return nil, err
		}
		ev := store.Event{
			Kind:      store.EventKind(kind),
			Timestamp: time.UnixMilli(ts).UTC(),
			Data:      data,
		}
		if note.Valid {
			ev.Note = note.String
		}
		out = append(out, ev)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

func StripANSI(b []byte) string {
	return ansiRegex.ReplaceAllString(string(b), "")
}

func ExtractCommandPairs(events []store.Event) []CommandPair {
	type boundary struct {
		cmd string
		ts  time.Time
	}

	// lineEditor simulates a readline-compatible line buffer with cursor tracking.
	// This correctly handles arrow keys, backspace/delete, and editing shortcuts
	// so that wraith reconstructs what was actually submitted, not the raw keystrokes.
	type lineEditor struct {
		buf []byte
		pos int // cursor position (0 = before buf[0], len(buf) = after last char)
	}
	ed := &lineEditor{}

	edInsert := func(b byte) {
		ed.buf = append(ed.buf, 0)
		copy(ed.buf[ed.pos+1:], ed.buf[ed.pos:])
		ed.buf[ed.pos] = b
		ed.pos++
	}
	edBackspace := func() {
		if ed.pos > 0 {
			ed.buf = append(ed.buf[:ed.pos-1], ed.buf[ed.pos:]...)
			ed.pos--
		}
	}
	edDelete := func() { // delete char at cursor (forward delete)
		if ed.pos < len(ed.buf) {
			ed.buf = append(ed.buf[:ed.pos], ed.buf[ed.pos+1:]...)
		}
	}
	edClear := func() {
		ed.buf = ed.buf[:0]
		ed.pos = 0
	}
	edKillToEnd := func() { // Ctrl+K
		ed.buf = ed.buf[:ed.pos]
	}
	edDeleteWord := func() { // Ctrl+W — delete word before cursor
		end := ed.pos
		// skip trailing spaces
		for end > 0 && ed.buf[end-1] == ' ' {
			end--
		}
		// skip word chars
		for end > 0 && ed.buf[end-1] != ' ' {
			end--
		}
		ed.buf = append(ed.buf[:end], ed.buf[ed.pos:]...)
		ed.pos = end
	}

	var boundaries []boundary

	// Escape state machine v2 — strict-discard consumer.
	//
	// KEY INVARIANT: No byte inside any escape sequence ever reaches edInsert().
	// Unknown sequences are fully consumed and silently discarded.
	// This prevents terminal weirdness (OSC shell integration, bracketed paste,
	// application-specific sequences) from corrupting command reconstruction.
	//
	// States:
	//   escNone  — normal input processing
	//   escEsc   — saw ESC (0x1B), deciding sequence type
	//   escCSI   — in CSI (ESC [), accumulating params until final byte
	//   escOSC   — in OSC (ESC ]) or DCS/APC/PM/SOS, consuming until BEL or ST
	//   escSS3   — in SS3 (ESC O), consuming one byte
	//   escST    — saw ESC inside a string sequence, expecting \ to complete ST
	//   escFe    — single-byte Fe sequence (ESC @–_), consuming one byte
	type escMode int
	const (
		escNone escMode = iota
		escEsc
		escCSI
		escOSC // also used for DCS, APC, PM, SOS — all terminate with ST or BEL
		escSS3
		escST
		escFe
	)

	esc := escNone
	var csiParam []byte

	for _, ev := range events {
		if ev.Kind != store.EventInput {
			continue
		}
		for _, b := range ev.Data {
			switch esc {
			case escEsc:
				switch {
				case b == '[':
					esc = escCSI
					csiParam = csiParam[:0]
				case b == ']':
					esc = escOSC // OSC
				case b == 'O':
					esc = escSS3 // SS3
				case b == 'P', b == '_', b == '^', b == 'X':
					esc = escOSC // DCS, APC, PM, SOS — all same termination rule
				case b == 0x1b:
					// ESC ESC — Alt/Meta prefix; stay in escEsc to consume next byte
				case b == 'b':
					// Alt+B — word backward
					for ed.pos > 0 && ed.buf[ed.pos-1] == ' ' {
						ed.pos--
					}
					for ed.pos > 0 && ed.buf[ed.pos-1] != ' ' {
						ed.pos--
					}
					esc = escNone
				case b == 'f':
					// Alt+F — word forward
					for ed.pos < len(ed.buf) && ed.buf[ed.pos] == ' ' {
						ed.pos++
					}
					for ed.pos < len(ed.buf) && ed.buf[ed.pos] != ' ' {
						ed.pos++
					}
					esc = escNone
				case b >= 0x40 && b <= 0x5f:
					// Fe sequence (ESC @–_): consume one more byte
					esc = escFe
				default:
					// Unknown ESC + byte — discard both, return to normal
					esc = escNone
				}

			case escCSI:
				if b >= 0x30 && b <= 0x3f {
					// Parameter byte — accumulate
					csiParam = append(csiParam, b)
					continue
				}
				if b >= 0x20 && b <= 0x2f {
					// Intermediate byte — accumulate (rare, but spec-correct)
					csiParam = append(csiParam, b)
					continue
				}
				// Final byte (0x40–0x7E) — dispatch recognized sequences, discard rest
				esc = escNone
				param := string(csiParam)
				switch b {
				case 'D': // cursor left
					if param == "1;5" {
						// Ctrl+Left — word backward
						for ed.pos > 0 && ed.buf[ed.pos-1] == ' ' {
							ed.pos--
						}
						for ed.pos > 0 && ed.buf[ed.pos-1] != ' ' {
							ed.pos--
						}
					} else {
						if ed.pos > 0 {
							ed.pos--
						}
					}
				case 'C': // cursor right
					if param == "1;5" {
						// Ctrl+Right — word forward
						for ed.pos < len(ed.buf) && ed.buf[ed.pos] == ' ' {
							ed.pos++
						}
						for ed.pos < len(ed.buf) && ed.buf[ed.pos] != ' ' {
							ed.pos++
						}
					} else {
						if ed.pos < len(ed.buf) {
							ed.pos++
						}
					}
				case 'H': // Home
					ed.pos = 0
				case 'F': // End
					ed.pos = len(ed.buf)
				case '~':
					switch param {
					case "3": // Delete key — forward delete
						edDelete()
					case "1", "7": // Home variants
						ed.pos = 0
					case "4", "8": // End variants
						ed.pos = len(ed.buf)
					}
					// All other ~ params (page up/down, F-keys, etc.) — discard
				}
				// All unrecognized CSI final bytes — discard (already esc=escNone)

			case escOSC:
				// Consuming OSC/DCS/APC/PM/SOS body.
				// Terminate on BEL (0x07) or start of ST (ESC \).
				if b == 0x07 {
					esc = escNone
				} else if b == 0x1b {
					esc = escST // saw ESC inside string — expect \ next
				}
				// All other bytes — consume silently

			case escST:
				// Second byte of ST (ESC \). Consume unconditionally and exit.
				esc = escNone

			case escSS3:
				// Single byte follows ESC O — dispatch cursor keys, discard rest
				esc = escNone
				switch b {
				case 'A': // up — ignore (history)
				case 'B': // down — ignore
				case 'C': // right
					if ed.pos < len(ed.buf) {
						ed.pos++
					}
				case 'D': // left
					if ed.pos > 0 {
						ed.pos--
					}
				case 'H': // Home
					ed.pos = 0
				case 'F': // End
					ed.pos = len(ed.buf)
				}
				// F1–F4 (P/Q/R/S) and anything else — discard

			case escFe:
				// Single-byte Fe sequence — consume and discard
				esc = escNone

			case escNone:
				switch {
				case b == 0x1b:
					esc = escEsc
				case b == 0x7f || b == 0x08:
					edBackspace()
				case b == 0x15:
					edClear()
				case b == 0x17:
					edDeleteWord()
				case b == 0x0b:
					edKillToEnd()
				case b == 0x01:
					ed.pos = 0
				case b == 0x05:
					ed.pos = len(ed.buf)
				case b == 0x02:
					if ed.pos > 0 {
						ed.pos--
					}
				case b == 0x06:
					if ed.pos < len(ed.buf) {
						ed.pos++
					}
				case b == 0x03 || b == 0x04:
					edClear()
				case b == '\r' || b == '\n':
					cmd := strings.TrimSpace(string(ed.buf))
					edClear()
					if cmd != "" {
						boundaries = append(boundaries, boundary{cmd: cmd, ts: ev.Timestamp})
					}
				case b >= 0x20 && b <= 0x7e:
					edInsert(b)
				// All other control bytes (0x00–0x1F not handled above) — discard
				}
			}
		}
	}

	if len(boundaries) == 0 {
		return nil
	}

	// Detect TUI windows from the output stream.
	// Alternate-screen entry/exit sequences mark periods when a full-screen TUI
	// (nano, vim, htop, msfconsole with TUI, etc.) is active.
	// During these windows we tag the launching command so the AI knows not to
	// interpret keystroke reconstruction artifacts as shell syntax.
	altScreenEnter := regexp.MustCompile(`\x1b\[(?:\?1049|\?1047|\?47)h`)
	altScreenExit := regexp.MustCompile(`\x1b\[(?:\?1049|\?1047|\?47)l`)

	var tuiWindows []tuiWindow
	var tuiOpen *tuiWindow
	for _, ev := range events {
		if ev.Kind != store.EventOutput {
			continue
		}
		raw := string(ev.Data)
		if altScreenEnter.MatchString(raw) && tuiOpen == nil {
			w := tuiWindow{start: ev.Timestamp}
			tuiWindows = append(tuiWindows, w)
			tuiOpen = &tuiWindows[len(tuiWindows)-1]
		}
		if altScreenExit.MatchString(raw) && tuiOpen != nil {
			tuiOpen.end = ev.Timestamp
			tuiOpen = nil
		}
	}

	// Helper: check if a time falls within any TUI window.
	inTUIWindow := func(t time.Time) bool {
		for _, w := range tuiWindows {
			if t.Before(w.start) {
				continue
			}
			if w.end.IsZero() || t.Before(w.end) {
				return true
			}
		}
		return false
	}

	type outputChunk struct {
		ts   time.Time
		text string
	}
	var outputChunks []outputChunk
	for _, ev := range events {
		if ev.Kind != store.EventOutput {
			continue
		}
		text := StripANSI(ev.Data)
		text = strings.ReplaceAll(text, "\r\n", "\n")
		text = strings.ReplaceAll(text, "\r", "\n")
		if text != "" {
			outputChunks = append(outputChunks, outputChunk{ts: ev.Timestamp, text: text})
		}
	}

	findNotFoundCmd := regexp.MustCompile(`(?m)Command '([^']+)' not found`)

	// Build output per command in one linear pass: advance a single pointer
	// through outputChunks as we iterate boundaries (both are sorted by ts).
	var pairs []CommandPair
	outIdx := 0 // index into outputChunks; only advances forward
	for i, b := range boundaries {
		var endTs time.Time
		if i+1 < len(boundaries) {
			endTs = boundaries[i+1].ts
		}

		// Skip output chunks that are before this command's timestamp.
		for outIdx < len(outputChunks) && outputChunks[outIdx].ts.Before(b.ts) {
			outIdx++
		}

		var sb strings.Builder
		for j := outIdx; j < len(outputChunks); j++ {
			if !endTs.IsZero() && !outputChunks[j].ts.Before(endTs) {
				break
			}
			sb.WriteString(outputChunks[j].text)
		}

		output := TruncateOutput(sb.String(), defaultMaxOutputLines)

		cmd := b.cmd
		// Heuristic: fix common apt case where a space sometimes goes missing in captured input.
		if strings.Contains(cmd, "apt install") && !strings.Contains(cmd, "apt install ") {
			cmd = strings.Replace(cmd, "apt install", "apt install ", 1)
			cmd = strings.Join(strings.Fields(cmd), " ")
		}
		// Heuristic: if output reports "Command 'X' not found" then the command token was X.
		if m := findNotFoundCmd.FindStringSubmatch(output); len(m) == 2 {
			x := m[1]
			parts := strings.Fields(cmd)
			if len(parts) > 0 && parts[0] != x {
				args := ""
				if len(parts) > 1 {
					args = " " + strings.Join(parts[1:], " ")
				}
				cmd = x + args
			}
		}

		// Heuristic: some sessions have incomplete input capture; if output indicates an nmap run, label it accordingly.
		if strings.TrimSpace(cmd) == "s" {
			lowerOut := strings.ToLower(output)
			if strings.Contains(lowerOut, "nmap") && (strings.Contains(lowerOut, "nmap scan") || strings.Contains(lowerOut, "starting nmap")) {
				cmd = "sudo nmap"
			}
		}

		targetSource := cmd
		if output != "" {
			if targetSource != "" {
				targetSource += "\n"
			}
			targetSource += output
		}
		targets := extractTargets(targetSource)

		// Check if this command launched a TUI (alternate-screen active shortly after)
		tuiMode := inTUIWindow(b.ts)
		tuiLabel := ""
		if tuiMode {
			// Extract the TUI process name from the command (first word)
			fields := strings.Fields(cmd)
			if len(fields) > 0 {
				tuiLabel = fields[0]
				// Strip sudo prefix
				if tuiLabel == "sudo" && len(fields) > 1 {
					tuiLabel = fields[1]
				}
			}
		}

		pairs = append(pairs, CommandPair{
			Index:     len(pairs) + 1,
			Command:   cmd,
			Output:    output,
			Timestamp: b.ts,
			Targets:   targets,
			TUIMode:   tuiMode,
			TUILabel:  tuiLabel,
		})
	}

	// Phase 3: inject operator notes as special command pairs
	for _, ev := range events {
		if ev.Kind != store.EventNote || ev.Note == "" {
			continue
		}
		pairs = append(pairs, CommandPair{
			Index:     len(pairs) + 1,
			Command:   "[operator note]",
			Output:    ev.Note,
			Timestamp: ev.Timestamp,
			Targets:   extractTargets(ev.Note),
		})
	}

	// Sort all pairs by timestamp
	sort.Slice(pairs, func(i, j int) bool {
		return pairs[i].Timestamp.Before(pairs[j].Timestamp)
	})
	// Re-assign indices after sort
	for i := range pairs {
		pairs[i].Index = i + 1
	}

	return pairs
}

func TruncateOutput(output string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = defaultMaxOutputLines
	}

	if summary, ok := summarizeNmap(output); ok {
		return summary
	}

	output = strings.TrimSpace(output)
	if output == "" {
		return ""
	}

	lines := strings.Split(output, "\n")
	if len(lines) <= maxLines {
		return output
	}

	const bannerLines = 5
	const tailLines = 3
	const maxSignalLines = 40

	bannerEnd := bannerLines
	if bannerEnd > len(lines) {
		bannerEnd = len(lines)
	}

	tailStart := len(lines) - tailLines
	if tailStart < bannerEnd {
		tailStart = bannerEnd
	}
	if tailStart < 0 {
		tailStart = 0
	}

	banner := lines[:bannerEnd]
	tail := lines[tailStart:]
	middle := lines[bannerEnd:tailStart]

	var signalLines []string
	for _, line := range middle {
		if isSignalLine(line) {
			signalLines = append(signalLines, line)
			if len(signalLines) >= maxSignalLines {
				break
			}
		}
	}

	var sb strings.Builder
	for _, l := range banner {
		sb.WriteString(l)
		sb.WriteByte('\n')
	}
	if len(signalLines) > 0 {
		sb.WriteString(fmt.Sprintf("[... %d lines — showing %d signal lines ...]\n", len(middle), len(signalLines)))
		for _, l := range signalLines {
			sb.WriteString(l)
			sb.WriteByte('\n')
		}
	} else {
		sb.WriteString(fmt.Sprintf("[... %d lines truncated ...]\n", len(middle)))
	}
	for i, l := range tail {
		sb.WriteString(l)
		if i < len(tail)-1 {
			sb.WriteByte('\n')
		}
	}

	return sb.String()
}

func isSignalLine(line string) bool {
	l := strings.TrimSpace(line)
	if l == "" {
		return false
	}
	noisePatterns := []string{
		"Progress:", "progress:", "[\\", "===", "---", "...",
		"Trying", "Testing", "Checking",
	}
	for _, p := range noisePatterns {
		if strings.Contains(l, p) {
			return false
		}
	}
	signalPatterns := []string{
		" 200 ", " 301 ", " 302 ", " 403 ", " 500 ", "(Status: 2", "(Status: 3", "(Status: 4",
		"Found:", "found:", "[+]", "[FOUND]",
		"open", "Open",
		"Login successful", "Login Success", "Valid credentials",
		"Username:", "Password:", "hash",
		"/usr/bin/", "/usr/local/", "cap_", "SUID", "SGID",
		"uid=0", "root",
	}
	for _, p := range signalPatterns {
		if strings.Contains(l, p) {
			return true
		}
	}
	return false
}

func summarizeNmap(output string) (string, bool) {
	if output == "" {
		return "", false
	}
	lowered := strings.ToLower(output)
	if !strings.Contains(lowered, "nmap scan report") {
		return "", false
	}

	// Keep informative lines, drop pure noise.
	// Noise: blank lines inside stats blocks, progress indicators, raw packet counts.
	noisePatterns := []string{
		"raw packets sent",
		"read data files from",
		"nmap done:",
		"warning:",
		"note:",
		"initiating",
		"completed",
		"stats:",
		"seconds elapsed",
	}

	var sb strings.Builder
	for _, line := range strings.Split(output, "\n") {
		trimmed := strings.TrimRight(line, " \t")
		lower := strings.ToLower(trimmed)

		// Always skip pure noise lines.
		skip := false
		for _, pat := range noisePatterns {
			if strings.Contains(lower, pat) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		// For port lines, skip closed/filtered — keep open and open|filtered.
		if strings.Contains(trimmed, "/tcp") || strings.Contains(trimmed, "/udp") {
			parts := strings.Fields(trimmed)
			if len(parts) >= 2 {
				state := strings.ToLower(parts[1])
				if state != "open" && state != "open|filtered" {
					continue
				}
			}
		}

		sb.WriteString(trimmed)
		sb.WriteByte('\n')
	}

	result := strings.TrimSpace(sb.String())
	if result == "" {
		return "", false
	}
	return result, true
}

func extractTargets(source string) []string {
	seen := map[string]struct{}{}
	output := []string{}

	for _, match := range ipv4Regex.FindAllString(source, -1) {
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		output = append(output, match)
	}

	for _, match := range hostnameRegex.FindAllString(source, -1) {
		if _, ok := seen[match]; ok {
			continue
		}
		seen[match] = struct{}{}
		output = append(output, match)
	}

	return output
}

func detectPrompt(line string) (string, bool) {
	trimmed := strings.TrimSpace(line)
	if trimmed == "" {
		return "", false
	}
	for _, marker := range promptMarkers {
		if strings.HasPrefix(trimmed, marker) {
			return trimmed[len(marker):], true
		}
	}
	for _, marker := range promptMarkers {
		if idx := strings.Index(trimmed, marker); idx >= 0 && idx < promptLookbackLimit {
			return trimmed[idx+len(marker):], true
		}
	}
	return "", false
}

func getDBConn(db *store.DB) (*sql.DB, error) {
	if db == nil {
		return nil, fmt.Errorf("store: nil db")
	}
	value := reflect.ValueOf(db).Elem().FieldByName("conn")
	if !value.IsValid() {
		return nil, fmt.Errorf("store: missing conn field")
	}

	connVal := reflect.NewAt(value.Type(), unsafe.Pointer(value.UnsafeAddr())).Elem()
	if connVal.IsNil() {
		return nil, fmt.Errorf("store: nil connection")
	}

	conn, ok := connVal.Interface().(*sql.DB)
	if !ok {
		return nil, fmt.Errorf("store: invalid connection type")
	}
	return conn, nil
}
