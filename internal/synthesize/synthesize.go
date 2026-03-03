package synthesize

import (
	"time"

	"github.com/google/uuid"
	"github.com/jallphin/wraith/internal/store"
)

// Run is a stub synthesizer. It returns mock findings so the review TUI
// can be exercised without an AI backend.
func Run(db *store.DB) ([]store.Finding, error) {
	now := time.Now().UTC()

	return []store.Finding{
		{
			ID:        uuid.NewString(),
			SessionID: db.SessionID,
			Title:     "Kerberoast → Domain Admin",
			Severity:  store.SeverityCritical,
			Asset:     "DC01.corp.local (10.1.0.5)",
			Technique: "T1558.003 — Kerberoasting",
			Phase:     store.PhaseLatMov,
			Narrative: "svc_backup held a weak password. The TGS ticket cracked offline quickly, yielding full domain admin credentials.",
			EventIDs:  []int64{},
			Status:    store.StatusProposed,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        uuid.NewString(),
			SessionID: db.SessionID,
			Title:     "SMB Share Misconfiguration",
			Severity:  store.SeverityHigh,
			Asset:     "FILE01.corp.local (10.1.0.22)",
			Technique: "T1135 — Network Share Discovery",
			Phase:     store.PhaseCollection,
			Narrative: "A sensitive share was accessible to low-privileged users, allowing retrieval of internal documents and password hints.",
			EventIDs:  []int64{},
			Status:    store.StatusProposed,
			CreatedAt: now,
			UpdatedAt: now,
		},
		{
			ID:        uuid.NewString(),
			SessionID: db.SessionID,
			Title:     "Password Reuse Across Hosts",
			Severity:  store.SeverityMedium,
			Asset:     "Multiple endpoints",
			Technique: "T1110 — Brute Force",
			Phase:     store.PhaseInitialAccess,
			Narrative: "Credentials recovered from one system were reused successfully to access additional hosts, expanding blast radius.",
			EventIDs:  []int64{},
			Status:    store.StatusProposed,
			CreatedAt: now,
			UpdatedAt: now,
		},
	}, nil
}
