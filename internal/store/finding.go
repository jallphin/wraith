package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"time"
)

// Severity represents finding severity.
//
// Stored as an int in SQLite.
type Severity int

const (
	SeverityInfo Severity = iota
	SeverityLow
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

func (s Severity) String() string {
	switch s {
	case SeverityInfo:
		return "INFO"
	case SeverityLow:
		return "LOW"
	case SeverityMedium:
		return "MEDIUM"
	case SeverityHigh:
		return "HIGH"
	case SeverityCritical:
		return "CRITICAL"
	default:
		return "UNKNOWN"
	}
}

// Color returns a lipgloss-compatible color string.
func (s Severity) Color() string {
	switch s {
	case SeverityInfo:
		return "241" // grey
	case SeverityLow:
		return "39" // blue
	case SeverityMedium:
		return "220" // yellow
	case SeverityHigh:
		return "208" // orange
	case SeverityCritical:
		return "196" // red
	default:
		return "7"
	}
}

// Phase is the engagement phase.
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

// FindingStatus is the operator review status.
type FindingStatus int

const (
	StatusProposed FindingStatus = iota
	StatusApproved
	StatusDiscarded
)

// Finding is an AI-proposed (and operator-reviewed) reportable item.
type Finding struct {
	ID         string
	SessionID  string
	Title      string
	Severity   Severity
	Asset      string
	Technique  string
	Phase      Phase
	Narrative  string
	CVE        string
	CVSSScore  float64
	CVSSVector string
	CWE        string
	CPE        string
	Tags       []string
	EventIDs   []int64
	Status     FindingStatus
	CreatedAt  time.Time
	UpdatedAt  time.Time
}

func (db *DB) SaveFinding(f Finding) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("store: nil db")
	}

	if f.ID == "" {
		return fmt.Errorf("store: finding missing id")
	}
	if f.SessionID == "" {
		f.SessionID = db.SessionID
	}
	if f.SessionID == "" {
		return fmt.Errorf("store: finding missing session id")
	}
	if f.Title == "" {
		return fmt.Errorf("store: finding missing title")
	}

	now := time.Now().UTC()
	if f.CreatedAt.IsZero() {
		f.CreatedAt = now
	}
	f.UpdatedAt = now

	eventIDsJSON, err := json.Marshal(f.EventIDs)
	if err != nil {
		return err
	}

	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return err
	}

	_, err = db.conn.Exec(
		`INSERT INTO findings (id, session_id, title, severity, asset, technique, phase, narrative, cve, cvss_score, cvss_vector, cwe, cpe, tags, event_ids, status, created_at, updated_at)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		f.ID,
		f.SessionID,
		f.Title,
		int(f.Severity),
		f.Asset,
		f.Technique,
		string(f.Phase),
		f.Narrative,
		f.CVE,
		f.CVSSScore,
		f.CVSSVector,
		f.CWE,
		f.CPE,
		string(tagsJSON),
		string(eventIDsJSON),
		int(f.Status),
		f.CreatedAt.UnixMilli(),
		f.UpdatedAt.UnixMilli(),
	)
	return err
}

func (db *DB) UpdateFinding(f Finding) error {
	if db == nil || db.conn == nil {
		return fmt.Errorf("store: nil db")
	}
	if f.ID == "" {
		return fmt.Errorf("store: finding missing id")
	}
	if f.SessionID == "" {
		f.SessionID = db.SessionID
	}

	f.UpdatedAt = time.Now().UTC()
	eventIDsJSON, err := json.Marshal(f.EventIDs)
	if err != nil {
		return err
	}

	tagsJSON, err := json.Marshal(f.Tags)
	if err != nil {
		return err
	}

	res, err := db.conn.Exec(
		`UPDATE findings
		 SET title=?, severity=?, asset=?, technique=?, phase=?, narrative=?, cve=?, cvss_score=?, cvss_vector=?, cwe=?, cpe=?, tags=?, event_ids=?, status=?, updated_at=?
		 WHERE id=?`,
		f.Title,
		int(f.Severity),
		f.Asset,
		f.Technique,
		string(f.Phase),
		f.Narrative,
		f.CVE,
		f.CVSSScore,
		f.CVSSVector,
		f.CWE,
		f.CPE,
		string(tagsJSON),
		string(eventIDsJSON),
		int(f.Status),
		f.UpdatedAt.UnixMilli(),
		f.ID,
	)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return sql.ErrNoRows
	}
	return nil
}

func (db *DB) LoadFindings(sessionID string) ([]Finding, error) {
	if db == nil || db.conn == nil {
		return nil, fmt.Errorf("store: nil db")
	}
	if sessionID == "" {
		sessionID = db.SessionID
	}

	rows, err := db.conn.Query(
		`SELECT id, session_id, title, severity, asset, technique, phase, narrative, cve, cvss_score, cvss_vector, cwe, cpe, tags, event_ids, status, created_at, updated_at
		 FROM findings
		 WHERE session_id=?
		 ORDER BY created_at ASC`,
		sessionID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Finding
	for rows.Next() {
		var f Finding
		var sev int
		var status int
		var phase string
		var cve string
		var cvssScore sql.NullFloat64
		var cvssVector string
		var cwe string
		var cpe string
		var tagsStr string
		var eventIDsStr string
		var createdMS, updatedMS int64
		if err := rows.Scan(
			&f.ID,
			&f.SessionID,
			&f.Title,
			&sev,
			&f.Asset,
			&f.Technique,
			&phase,
			&f.Narrative,
			&cve,
			&cvssScore,
			&cvssVector,
			&cwe,
			&cpe,
			&tagsStr,
			&eventIDsStr,
			&status,
			&createdMS,
			&updatedMS,
		); err != nil {
			return nil, err
		}
		f.Severity = Severity(sev)
		f.Status = FindingStatus(status)
		f.Phase = Phase(phase)
		f.CVE = cve
		if cvssScore.Valid {
			f.CVSSScore = cvssScore.Float64
		}
		f.CVSSVector = cvssVector
		f.CWE = cwe
		f.CPE = cpe
		if tagsStr != "" {
			_ = json.Unmarshal([]byte(tagsStr), &f.Tags)
		}
		if eventIDsStr != "" {
			_ = json.Unmarshal([]byte(eventIDsStr), &f.EventIDs)
		}
		f.CreatedAt = time.UnixMilli(createdMS).UTC()
		f.UpdatedAt = time.UnixMilli(updatedMS).UTC()
		out = append(out, f)
	}
	return out, rows.Err()
}
