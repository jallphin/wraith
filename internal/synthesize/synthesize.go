package synthesize

import (
	"fmt"
	"time"

	"github.com/jallphin/wraith/internal/store"
)

func Run(db *store.DB) ([]store.Finding, error) {
	if db == nil {
		return nil, fmt.Errorf("synthesize: nil db")
	}

	events, err := LoadEvents(db)
	if err != nil {
		return nil, err
	}

	pairs := ExtractCommandPairs(events)
	if len(pairs) == 0 {
		return nil, nil
	}

	// Save each command pair as a note event; collect row IDs for evidence linking.
	pairRowIDs := make([]int64, len(pairs))
	for i, p := range pairs {
		rowID, err := db.SaveCommandPairNote(p.Timestamp, p.Command, p.Output)
		if err != nil {
			// Non-fatal: evidence linking degrades gracefully.
			pairRowIDs[i] = 0
		} else {
			pairRowIDs[i] = rowID
		}
	}

	phases := ClusterPairs(pairs, 5*time.Minute)
	prompt := BuildPrompt(phases, db.SessionID)

	response, err := CallAI(prompt)
	if err != nil {
		return nil, err
	}

	findings, err := ParseFindings(response, db.SessionID, pairRowIDs)
	if err != nil {
		return nil, err
	}

	for _, finding := range findings {
		if err := db.SaveFinding(finding); err != nil {
			return nil, err
		}
	}

	return findings, nil
}
