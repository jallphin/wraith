// Package store manages the SQLite event log for a wraith session.
package store

import (
	"database/sql"
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
		INSERT OR IGNORE INTO meta (key, value) VALUES ('session_id', ?);
	`, sessionID); err != nil {
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
