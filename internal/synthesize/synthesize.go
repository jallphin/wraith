package synthesize

import (
	"fmt"
	"time"

	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
)

// Stage constants for progress reporting.
type Stage int

const (
	StageEvents   Stage = iota // Loading session events
	StagePairs                 // Extracting command pairs
	StageClusters              // Clustering activity phases
	StagePrompt                // Building prompt
	StageAI                    // Waiting for AI response
	StageSave                  // Saving findings
)

// ProgressFunc is called at each stage transition. label is a human-readable
// status string (e.g. "Sending to AI for analysis (~12k tokens)").
type ProgressFunc func(stage Stage, label string)

func Run(db *store.DB, cfg config.Config) ([]store.Finding, error) {
	return RunWithProgress(db, cfg, nil)
}

func RunWithProgress(db *store.DB, cfg config.Config, progress ProgressFunc) ([]store.Finding, error) {
	report := func(stage Stage, label string) {
		if progress != nil {
			progress(stage, label)
		}
	}

	if db == nil {
		return nil, fmt.Errorf("synthesize: nil db")
	}

	report(StageEvents, "Loading session events")
	events, err := LoadEvents(db)
	if err != nil {
		return nil, err
	}

	report(StagePairs, "Extracting command pairs")
	pairs := ExtractCommandPairs(events)
	if len(pairs) == 0 {
		return nil, nil
	}

	// Save each command pair as a note event; collect row IDs for evidence linking.
	pairRowIDs := make([]int64, len(pairs))
	for i, p := range pairs {
		rowID, err := db.SaveCommandPairNote(p.Timestamp, p.Command, p.Output)
		if err != nil {
			pairRowIDs[i] = 0
		} else {
			pairRowIDs[i] = rowID
		}
	}

	report(StageClusters, fmt.Sprintf("Clustering %d command pairs into phases", len(pairs)))
	phases := ClusterPairs(pairs, 5*time.Minute)

	report(StagePrompt, "Building prompt")
	prompt := BuildPrompt(phases, db.SessionID, cfg)

	// Estimate token count: ~4 chars per token is a reasonable heuristic.
	estTokens := len(prompt) / 4
	report(StageAI, fmt.Sprintf("Sending to AI for analysis (~%dk tokens)", estTokens/1000))

	response, err := CallAI(prompt, cfg)
	if err != nil {
		return nil, err
	}

	report(StageSave, "Parsing and saving findings")
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
