package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
)

type ExportEvidence struct {
	Timestamp string `json:"timestamp"`
	Command   string `json:"command"`
	Output    string `json:"output"`
}

type ExportFinding struct {
	ID         string           `json:"id"`
	Title      string           `json:"title"`
	Severity   string           `json:"severity"`
	CVSSScore  *float64         `json:"cvss_score"`
	CVSSVector string           `json:"cvss_vector,omitempty"`
	CVE        string           `json:"cve,omitempty"`
	CWE        string           `json:"cwe,omitempty"`
	CPE        string           `json:"cpe,omitempty"`
	Asset      string           `json:"asset,omitempty"`
	Technique  string           `json:"technique,omitempty"`
	Phase      string           `json:"phase,omitempty"`
	Narrative  string           `json:"narrative,omitempty"`
	Tags       []string         `json:"tags"`
	Evidence   []ExportEvidence `json:"evidence"`
}

type ExportSession struct {
	ID           string `json:"id"`
	Start        string `json:"start,omitempty"`
	End          string `json:"end,omitempty"`
	Duration     string `json:"duration,omitempty"`
	EventCount   int    `json:"event_count,omitempty"`
	FindingCount int    `json:"finding_count,omitempty"`
}

type ExportSummary struct {
	FindingsCount  int            `json:"findings_count"`
	SeverityCounts map[string]int `json:"severity_counts"`
	Tags           []string       `json:"tags"`
}

type ExportReport struct {
	SchemaVersion string                  `json:"schema_version"`
	Engagement    config.EngagementConfig `json:"engagement"`
	Session       ExportSession           `json:"session"`
	Findings      []ExportFinding         `json:"findings"`
	Summary       ExportSummary           `json:"summary"`
}

func ExportApproved(db *store.DB, meta store.SessionMeta, findings []store.Finding, cfg config.Config) (jsonPath, mdPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	outDir := filepath.Join(home, ".wraith", "exports", meta.ID)
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", "", err
	}

	var approved []store.Finding
	for _, f := range findings {
		if f.Status == store.StatusApproved {
			approved = append(approved, f)
		}
	}

	jsonPath, err = ExportJSON(outDir, meta, approved, db, cfg)
	if err != nil {
		return "", "", err
	}

	mdPath = filepath.Join(outDir, "findings.md")
	md := &strings.Builder{}
	fmt.Fprintf(md, "# Findings — Session %s\n\n", meta.ID)
	if cfg.Engagement.ID != "" {
		fmt.Fprintf(md, "**Engagement:** %s | **Client:** %s\n", cfg.Engagement.ID, cfg.Engagement.Client)
		if len(cfg.Engagement.Scope) > 0 {
			fmt.Fprintf(md, "**Scope:** %s\n", strings.Join(cfg.Engagement.Scope, ", "))
		}
		fmt.Fprintln(md)
	}
	fmt.Fprintf(md, "**Events:** %d  •  **Findings:** %d\n\n", meta.EventCount, meta.FindingCount)

	for _, f := range approved {
		fmt.Fprintf(md, "## [%s] %s\n\n", f.Severity.String(), f.Title)
		if f.Asset != "" {
			fmt.Fprintf(md, "**Asset:** %s\n", f.Asset)
		}
		if f.Technique != "" {
			fmt.Fprintf(md, "**Technique:** %s\n", f.Technique)
		}
		if f.Phase != "" {
			fmt.Fprintf(md, "**Phase:** %s\n", f.Phase)
		}
		if f.CVE != "" {
			fmt.Fprintf(md, "**CVE:** %s\n", f.CVE)
		}
		if f.CVSSScore != 0 {
			fmt.Fprintf(md, "**CVSS Score:** %.1f\n", f.CVSSScore)
		}
		if f.CVSSVector != "" {
			fmt.Fprintf(md, "**CVSS Vector:** %s\n", f.CVSSVector)
		}
		if f.CWE != "" {
			fmt.Fprintf(md, "**CWE:** %s\n", f.CWE)
		}
		if f.CPE != "" {
			fmt.Fprintf(md, "**CPE:** %s\n", f.CPE)
		}
		if len(f.Tags) > 0 {
			fmt.Fprintf(md, "**Tags:** %s\n", strings.Join(f.Tags, ", "))
		}
		if len(f.EventIDs) > 0 {
			fmt.Fprintf(md, "**Evidence events:** %d\n", len(f.EventIDs))
		}
		fmt.Fprintf(md, "\n%s\n\n", strings.TrimSpace(f.Narrative))
	}

	if err := os.WriteFile(mdPath, []byte(strings.TrimSpace(md.String())+"\n"), 0600); err != nil {
		return "", "", err
	}

	return jsonPath, mdPath, nil
}

func ExportJSON(outDir string, meta store.SessionMeta, findings []store.Finding, db *store.DB, cfg config.Config) (string, error) {
	report := ExportReport{
		SchemaVersion: "1.0",
		Engagement:    cfg.Engagement,
		Session: ExportSession{
			ID:           meta.ID,
			Start:        formatTime(meta.Start),
			End:          formatTime(meta.End),
			Duration:     formatDuration(meta.Duration),
			EventCount:   meta.EventCount,
			FindingCount: len(findings),
		},
		Findings: make([]ExportFinding, 0, len(findings)),
	}

	summary := ExportSummary{
		FindingsCount:  len(findings),
		SeverityCounts: map[string]int{},
	}
	tagSet := map[string]struct{}{}

	for _, f := range findings {
		sev := f.Severity.String()
		if sev == "" {
			sev = "INFO"
		}
		summary.SeverityCounts[sev]++
		for _, tag := range f.Tags {
			tag = strings.ToLower(strings.TrimSpace(tag))
			if tag == "" {
				continue
			}
			tagSet[tag] = struct{}{}
		}
		report.Findings = append(report.Findings, ExportFinding{
			ID:         f.ID,
			Title:      f.Title,
			Severity:   sev,
			CVSSScore:  optionalFloat(f.CVSSScore),
			CVSSVector: f.CVSSVector,
			CVE:        f.CVE,
			CWE:        f.CWE,
			CPE:        f.CPE,
			Asset:      f.Asset,
			Technique:  f.Technique,
			Phase:      string(f.Phase),
			Narrative:  f.Narrative,
			Tags:       f.Tags,
			Evidence:   buildEvidence(db, f.EventIDs),
		})
	}

	tags := make([]string, 0, len(tagSet))
	for tag := range tagSet {
		tags = append(tags, tag)
	}
	sort.Strings(tags)
	summary.Tags = tags
	report.Summary = summary

	jsonPath := filepath.Join(outDir, "report.json")
	data, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return "", err
	}
	if err := os.WriteFile(jsonPath, data, 0600); err != nil {
		return "", err
	}
	return jsonPath, nil
}

func buildEvidence(db *store.DB, ids []int64) []ExportEvidence {
	if db == nil || len(ids) == 0 {
		return nil
	}
	events, err := db.LoadEventsByID(ids)
	if err != nil {
		return nil
	}
	var out []ExportEvidence
	for _, ev := range events {
		if ev.Note == "" {
			continue
		}
		cmd, output := parseCommandNote(ev.Note)
		out = append(out, ExportEvidence{
			Timestamp: ev.Timestamp.Format(time.RFC3339),
			Command:   cmd,
			Output:    output,
		})
	}
	return out
}

func parseCommandNote(note string) (string, string) {
	note = strings.TrimSpace(note)
	if note == "" {
		return "", ""
	}
	parts := strings.SplitN(note, "\n\n", 2)
	cmd := strings.TrimSpace(strings.TrimPrefix(parts[0], "$ "))
	var output string
	if len(parts) > 1 {
		output = strings.TrimSpace(parts[1])
	}
	return cmd, output
}

func optionalFloat(value float64) *float64 {
	if value == 0 {
		return nil
	}
	v := value
	return &v
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

func formatDuration(d time.Duration) string {
	if d <= 0 {
		return ""
	}
	return d.String()
}
