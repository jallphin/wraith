package tui

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/jallphin/wraith/internal/store"
)

type exportFinding struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Asset     string `json:"asset,omitempty"`
	Technique string `json:"technique,omitempty"`
	Phase     string `json:"phase,omitempty"`
	Narrative string `json:"narrative,omitempty"`
}

type exportBundle struct {
	SessionID    string          `json:"session_id"`
	ExportedAt   string          `json:"exported_at"`
	Findings     []exportFinding `json:"findings"`
	FindingCount int             `json:"finding_count"`
}

func ExportApproved(sessionID string, findings []store.Finding) (jsonPath, mdPath string, err error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", "", err
	}
	outDir := filepath.Join(home, ".wraith", "sessions")
	if err := os.MkdirAll(outDir, 0700); err != nil {
		return "", "", err
	}

	var approved []store.Finding
	for _, f := range findings {
		if f.Status == store.StatusApproved {
			approved = append(approved, f)
		}
	}

	bundle := exportBundle{
		SessionID:    sessionID,
		ExportedAt:   time.Now().UTC().Format(time.RFC3339),
		FindingCount: len(approved),
	}
	for _, f := range approved {
		bundle.Findings = append(bundle.Findings, exportFinding{
			ID:        f.ID,
			Title:     f.Title,
			Severity:  f.Severity.String(),
			Asset:     f.Asset,
			Technique: f.Technique,
			Phase:     string(f.Phase),
			Narrative: f.Narrative,
		})
	}

	jsonPath = filepath.Join(outDir, fmt.Sprintf("%s-findings.json", sessionID))
	mdPath = filepath.Join(outDir, fmt.Sprintf("%s-findings.md", sessionID))

	b, err := json.MarshalIndent(bundle, "", "  ")
	if err != nil {
		return "", "", err
	}
	if err := os.WriteFile(jsonPath, b, 0600); err != nil {
		return "", "", err
	}

	md := &strings.Builder{}
	fmt.Fprintf(md, "# Findings — Session %s\n\n", sessionID)
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
		fmt.Fprintf(md, "\n%s\n\n", strings.TrimSpace(f.Narrative))
	}

	if err := os.WriteFile(mdPath, []byte(md.String()), 0600); err != nil {
		return "", "", err
	}

	return jsonPath, mdPath, nil
}
