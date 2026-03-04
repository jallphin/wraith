package store

import (
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	_ "modernc.org/sqlite"
)

// SessionMeta is a lightweight listing of a session DB.
type SessionMeta struct {
	ID           string
	Path         string
	Start        time.Time
	End          time.Time
	Duration     time.Duration
	EventCount   int
	FindingCount int
}

// OpenSession opens an existing session database by path.
func OpenSession(path string) (*DB, error) {
	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}

	// Ensure findings table exists (older sessions might not have it yet).
	_, _ = conn.Exec(`
		CREATE TABLE IF NOT EXISTS findings (
		id          TEXT    PRIMARY KEY,
		session_id  TEXT    NOT NULL,
		title       TEXT    NOT NULL,
		severity    INTEGER NOT NULL,
		asset       TEXT,
		technique   TEXT,
		phase       TEXT,
		narrative   TEXT,
		cve         TEXT,
		cvss_score  REAL,
		cvss_vector TEXT,
		cwe         TEXT,
		cpe         TEXT,
		tags        TEXT,
		event_ids   TEXT,
		status      INTEGER NOT NULL DEFAULT 0,
		created_at  INTEGER NOT NULL,
		updated_at  INTEGER NOT NULL
		);
	`)

	// Best-effort: determine session id from meta or filename.
	sessionID := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	var metaID string
	_ = conn.QueryRow(`SELECT value FROM meta WHERE key='session_id'`).Scan(&metaID)
	if metaID != "" {
		sessionID = metaID
	}

	if err := ensureFindingColumns(conn); err != nil {
		conn.Close()
		return nil, err
	}

	return &DB{conn: conn, SessionID: sessionID}, nil
}

// ListSessions scans dir for *.db session files.
func ListSessions(dir string) ([]SessionMeta, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var metas []SessionMeta
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		name := e.Name()
		if !strings.HasSuffix(name, ".db") {
			continue
		}
		path := filepath.Join(dir, name)
		meta, err := InspectSession(path)
		if err != nil {
			// skip unreadable/corrupt sessions
			continue
		}
		metas = append(metas, meta)
	}

	sort.Slice(metas, func(i, j int) bool { return metas[i].Start.After(metas[j].Start) })
	return metas, nil
}

// InspectSession reads summary info from an existing session DB.
func InspectSession(path string) (SessionMeta, error) {
	db, err := OpenSession(path)
	if err != nil {
		return SessionMeta{}, err
	}
	defer db.Close()

	meta := SessionMeta{Path: path, ID: db.SessionID}

	var minTS, maxTS sql.NullInt64
	if err := db.conn.QueryRow(`SELECT MIN(ts), MAX(ts), COUNT(1) FROM events`).Scan(&minTS, &maxTS, &meta.EventCount); err != nil {
		return SessionMeta{}, err
	}
	if minTS.Valid {
		meta.Start = time.UnixMilli(minTS.Int64).UTC()
	}
	if maxTS.Valid {
		meta.End = time.UnixMilli(maxTS.Int64).UTC()
		meta.Duration = meta.End.Sub(meta.Start)
	}

	// Findings table might not exist in older sessions.
	var findingCount int
	if err := db.conn.QueryRow(`SELECT COUNT(1) FROM findings`).Scan(&findingCount); err == nil {
		meta.FindingCount = findingCount
	}

	if meta.ID == "" {
		meta.ID = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}

	return meta, nil
}

// MostRecentSession returns the newest session by timestamp.
func MostRecentSession(dir string) (SessionMeta, error) {
	metas, err := ListSessions(dir)
	if err != nil {
		return SessionMeta{}, err
	}
	if len(metas) == 0 {
		return SessionMeta{}, fmt.Errorf("no sessions found")
	}
	return metas[0], nil
}

func FindSession(dir, id string) (SessionMeta, error) {
	if id == "" {
		return MostRecentSession(dir)
	}
	sessions, err := ListSessions(dir)
	if err != nil {
		return SessionMeta{}, err
	}
	for _, s := range sessions {
		if s.ID == id || strings.HasPrefix(s.ID, id) {
			return s, nil
		}
	}
	return SessionMeta{}, fmt.Errorf("session not found: %s", id)
}

// LoadEventTexts loads event records by id and returns printable strings.
func (db *DB) LoadEventTexts(ids []int64) ([]string, error) {
	if len(ids) == 0 {
		return nil, nil
	}

	seen := map[string]struct{}{} // deduplicate identical evidence blocks
	out := make([]string, 0, len(ids))
	for _, id := range ids {
		var kind string
		var tsMS int64
		var data []byte
		var note sql.NullString
		if err := db.conn.QueryRow(`SELECT kind, ts, data, note FROM events WHERE id=?`, id).Scan(&kind, &tsMS, &data, &note); err != nil {
			continue
		}

		var text string
		if note.Valid {
			text = strings.TrimSpace(note.String)
		} else {
			text = strings.TrimSpace(string(data))
		}

		// Skip empty or placeholder-only entries.
		if text == "" || text == "$ [operator note]" || text == "[operator note]" {
			continue
		}

		// Deduplicate: skip if we've already included this exact content.
		if _, dup := seen[text]; dup {
			continue
		}
		seen[text] = struct{}{}

		ts := time.UnixMilli(tsMS).UTC().Format("2006-01-02 15:04:05 UTC")

		// Clean up the text: truncate runaway syslog/audit lines (key=value chains).
		cleaned := cleanEvidenceText(text)
		out = append(out, fmt.Sprintf("[%s]\n%s", ts, cleaned))
	}
	return out, nil
}

// SaveCommandPairNote saves a reconstructed command pair as a note event for evidence linking.
// Returns the inserted row ID.
func (db *DB) SaveCommandPairNote(ts time.Time, command, output string) (int64, error) {
	var text string
	if output != "" {
		text = "$ " + command + "\n\n" + output
	} else {
		text = "$ " + command
	}
	result, err := db.conn.Exec(
		`INSERT INTO events (kind, ts, data, note) VALUES (?, ?, ?, ?)`,
		"note",
		ts.UnixMilli(),
		nil,
		text,
	)
	if err != nil {
		return 0, err
	}
	return result.LastInsertId()
}

// SaveCommandPairNotesBatch saves multiple command pair notes in a single transaction.
// Returns a slice of row IDs in the same order as inputs; 0 for any that failed.
func (db *DB) SaveCommandPairNotesBatch(commands []string, outputs []string, timestamps []time.Time) ([]int64, error) {
	if len(commands) == 0 {
		return nil, nil
	}
	tx, err := db.conn.Begin()
	if err != nil {
		return nil, err
	}
	stmt, err := tx.Prepare(`INSERT INTO events (kind, ts, data, note) VALUES (?, ?, ?, ?)`)
	if err != nil {
		tx.Rollback()
		return nil, err
	}
	defer stmt.Close()

	ids := make([]int64, len(commands))
	for i := range commands {
		var text string
		if outputs[i] != "" {
			text = "$ " + commands[i] + "\n\n" + outputs[i]
		} else {
			text = "$ " + commands[i]
		}
		ts := timestamps[i]
		result, err := stmt.Exec("note", ts.UnixMilli(), nil, text)
		if err != nil {
			ids[i] = 0
		} else {
			id, _ := result.LastInsertId()
			ids[i] = id
		}
	}
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return ids, nil
}

// cleanEvidenceText sanitizes raw evidence text for display.
// Filters and truncates noise lines that would clutter the evidence view.
func cleanEvidenceText(text string) string {
	const maxLineLen = 160
	lines := strings.Split(text, "\n")
	out := lines[:0]
	for _, line := range lines {
		// Drop structured audit/syslog lines: contain multiple key=value; pairs
		// e.g. "tart=ae00f8ab;user=ike;hostname=expressway.htb;machineid=..."
		if strings.Count(line, "=") >= 4 && strings.Count(line, ";") >= 3 {
			continue
		}
		// Truncate any remaining long lines
		if len(line) > maxLineLen {
			line = line[:maxLineLen] + " [...]"
		}
		out = append(out, line)
	}
	return strings.Join(out, "\n")
}
