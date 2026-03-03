package synthesize

import (
	"database/sql"
	"fmt"
	"reflect"
	"regexp"
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
	var pairs []CommandPair
	var current *CommandPair
	var outputLines []string

	flush := func() {
		if current == nil {
			return
		}
		output := strings.Join(outputLines, "\n")
		condensed := TruncateOutput(output, defaultMaxOutputLines)
		targetSource := current.Command
		if condensed != "" {
			if targetSource != "" {
				targetSource += "\n"
			}
			targetSource += condensed
		}
		current.Output = condensed
		current.Targets = extractTargets(targetSource)
		if current.Command != "" || current.Output != "" {
			pairs = append(pairs, *current)
		}
		current = nil
		outputLines = outputLines[:0]
	}

	for _, ev := range events {
		if ev.Kind != store.EventOutput {
			continue
		}
		raw := StripANSI(ev.Data)
		if raw == "" {
			continue
		}
		raw = strings.ReplaceAll(raw, "\r", "")
		lines := strings.Split(raw, "\n")
		for _, line := range lines {
			if line == "" && current == nil {
				continue
			}
			if cmd, ok := detectPrompt(line); ok {
				flush()
				trimmed := strings.TrimSpace(cmd)
				if trimmed == "" {
					current = nil
					outputLines = outputLines[:0]
					continue
				}
				current = &CommandPair{
					Command:   trimmed,
					Timestamp: ev.Timestamp,
				}
				outputLines = outputLines[:0]
				continue
			}
			if current != nil {
				outputLines = append(outputLines, line)
			}
		}
	}
	flush()
	return pairs
}

func TruncateOutput(output string, maxLines int) string {
	if maxLines <= 0 {
		maxLines = defaultMaxOutputLines
	}
	if summary, ok := summarizeNmap(output); ok {
		output = summary
	}
	if output == "" {
		return ""
	}

	lines := strings.Split(output, "\n")
	if len(lines) <= maxLines {
		return output
	}

	head := 20
	tail := 5
	if head+tail >= len(lines) {
		head = len(lines) - tail
		if head < 0 {
			head = 0
		}
	}

	var sb strings.Builder
	for i := 0; i < head; i++ {
		sb.WriteString(lines[i])
		sb.WriteByte('\n')
	}

	skipped := len(lines) - head - tail
	if skipped > 0 {
		sb.WriteString(fmt.Sprintf("[... %d lines truncated ...]\n", skipped))
	}

	start := len(lines) - tail
	if start < head {
		start = head
	}
	for i := start; i < len(lines); i++ {
		sb.WriteString(lines[i])
		if i < len(lines)-1 {
			sb.WriteByte('\n')
		}
	}

	return sb.String()
}

func summarizeNmap(output string) (string, bool) {
	if output == "" {
		return "", false
	}
	lowered := strings.ToLower(output)
	if !strings.Contains(lowered, "nmap scan report") {
		return "", false
	}

	hosts := []string{}
	ports := []string{}
	seenHosts := map[string]struct{}{}
	seenPorts := map[string]struct{}{}

	for _, line := range strings.Split(output, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Nmap scan report for ") {
			host := strings.TrimPrefix(line, "Nmap scan report for ")
			if host != "" {
				if _, ok := seenHosts[host]; !ok {
					seenHosts[host] = struct{}{}
					hosts = append(hosts, host)
				}
			}
		}
		if strings.Contains(line, "/tcp") {
			parts := strings.Fields(line)
			if len(parts) > 0 {
				port := parts[0]
				if _, ok := seenPorts[port]; !ok {
					seenPorts[port] = struct{}{}
					ports = append(ports, port)
				}
			}
		}
	}

	if len(hosts) == 0 && len(ports) == 0 {
		return "", false
	}

	var sb strings.Builder
	sb.WriteString("Nmap scan summary:\n")
	if len(hosts) > 0 {
		sb.WriteString("Hosts: ")
		sb.WriteString(strings.Join(hosts, ", "))
		sb.WriteByte('\n')
	}
	if len(ports) > 0 {
		sb.WriteString("Ports: ")
		sb.WriteString(strings.Join(ports, ", "))
		sb.WriteByte('\n')
	}
	summary := strings.TrimRight(sb.String(), "\n")
	return summary, true
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
