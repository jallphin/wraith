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

	var boundaries []boundary
	var inputBuf []byte
	escState := 0
	for _, ev := range events {
		if ev.Kind != store.EventInput {
			continue
		}
		for _, b := range ev.Data {
			// Escape sequence handling (arrow keys, home/end, etc).
			// We want to ignore *all* bytes of sequences like: ESC [ A
			//  escState: 0=none, 1=after ESC, 2=in CSI/SS3 sequence
			if escState != 0 {
				if escState == 1 {
					if b == '[' || b == 'O' {
						escState = 2
					} else {
						// Unknown 2-byte escape, ignore and reset.
						escState = 0
					}
					continue
				}
				// escState == 2: consume until final byte (0x40-0x7e).
				if b >= 0x40 && b <= 0x7e {
					escState = 0
				}
				continue
			}

			switch {
			case b == 0x1b:
				// Start of escape sequence.
				escState = 1
			case b == 0x7f || b == 0x08:
				if len(inputBuf) > 0 {
					inputBuf = inputBuf[:len(inputBuf)-1]
				}
			case b == '\r' || b == '\n':
				cmd := strings.TrimSpace(string(inputBuf))
				inputBuf = inputBuf[:0]
				if cmd != "" {
					boundaries = append(boundaries, boundary{cmd: cmd, ts: ev.Timestamp})
				}
			case b >= 0x20 && b <= 0x7e:
				inputBuf = append(inputBuf, b)
			}
		}
	}

	if len(boundaries) == 0 {
		return nil
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

		pairs = append(pairs, CommandPair{
			Index:     len(pairs) + 1,
			Command:   cmd,
			Output:    output,
			Timestamp: b.ts,
			Targets:   targets,
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
