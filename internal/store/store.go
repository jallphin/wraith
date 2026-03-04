// Package store manages the SQLite event log for a wraith session.
package store

import (
	"database/sql"
	"errors"
	"fmt"
	"path/filepath"
	"time"

	_ "modernc.org/sqlite"
)

// EventKind distinguishes terminal input from output.
type EventKind string

const (
	EventInput  EventKind = "input"
	EventOutput EventKind = "output"
	EventNote   EventKind = "note" // operator-dropped context notes (future)
)

// Event is a single captured moment in a session.
type Event struct {
	Kind      EventKind
	Timestamp time.Time
	Data      []byte
	Note      string // only for EventNote
}

// DB wraps the SQLite connection for a session.
type DB struct {
	conn      *sql.DB
	SessionID string
}

// NewSession opens (or creates) a session database and returns an open DB.
func NewSession(dir string) (*DB, string, error) {
	sessionID := fmt.Sprintf("%d", time.Now().UnixMilli())
	path := filepath.Join(dir, sessionID+".db")

	conn, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, "", err
	}

	if _, err := conn.Exec(`
		CREATE TABLE IF NOT EXISTS events (
			id        INTEGER PRIMARY KEY AUTOINCREMENT,
			kind      TEXT    NOT NULL,
			ts        INTEGER NOT NULL,
			data      BLOB,
			note      TEXT
		);
		CREATE TABLE IF NOT EXISTS meta (
			key   TEXT PRIMARY KEY,
			value TEXT
		);
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
		INSERT OR IGNORE INTO meta (key, value) VALUES ('session_id', ?);
	`, sessionID); err != nil {
		conn.Close()
		return nil, "", err
	}

	if err := ensureFindingColumns(conn); err != nil {
		conn.Close()
		return nil, "", err
	}

	return &DB{conn: conn, SessionID: sessionID}, sessionID, nil
}

// WriteEvent appends an event to the session database.
func (db *DB) WriteEvent(e Event) error {
	_, err := db.conn.Exec(
		`INSERT INTO events (kind, ts, data, note) VALUES (?, ?, ?, ?)`,
		string(e.Kind),
		e.Timestamp.UnixMilli(),
		e.Data,
		e.Note,
	)
	return err
}

// Close closes the underlying database connection.
func (db *DB) Close() error {
	return db.conn.Close()
}

func ensureFindingColumns(conn *sql.DB) error {
	rows, err := conn.Query(`PRAGMA table_info(findings)`)
	if err != nil {
		return err
	}
	defer rows.Close()

	existing := make(map[string]struct{})
	for rows.Next() {
		var cid int
		var name string
		var colType string
		var notnull int
		var dflt sql.NullString
		var pk int
		if err := rows.Scan(&cid, &name, &colType, &notnull, &dflt, &pk); err != nil {
			return err
		}
		existing[name] = struct{}{}
	}
	if err := rows.Err(); err != nil {
		return err
	}

	cols := []struct {
		name string
		def  string
	}{
		{name: "cve", def: "cve TEXT"},
		{name: "cvss_score", def: "cvss_score REAL"},
		{name: "cvss_vector", def: "cvss_vector TEXT"},
		{name: "cwe", def: "cwe TEXT"},
		{name: "cpe", def: "cpe TEXT"},
		{name: "tags", def: "tags TEXT"},
	}
	for _, col := range cols {
		if _, ok := existing[col.name]; ok {
			continue
		}
		if _, err := conn.Exec(fmt.Sprintf("ALTER TABLE findings ADD COLUMN %s", col.def)); err != nil {
			return err
		}
	}
	return nil
}

func (db *DB) LoadEventsByID(ids []int64) ([]Event, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("store: nil db")
	}
	if len(ids) == 0 {
		return nil, nil
	}
	out := make([]Event, 0, len(ids))
	for _, id := range ids {
		var kind string
		var tsMS int64
		var data []byte
		var note sql.NullString
		if err := db.conn.QueryRow(`SELECT kind, ts, data, note FROM events WHERE id=?`, id).Scan(&kind, &tsMS, &data, &note); err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				continue
			}
			return nil, err
		}
		evt := Event{
			Kind:      EventKind(kind),
			Timestamp: time.UnixMilli(tsMS).UTC(),
			Data:      data,
		}
		if note.Valid {
			evt.Note = note.String
		}
		out = append(out, evt)
	}
	return out, nil
}
