package synthesize

import (
	"fmt"
	"sort"
	"time"
)

type Phase struct {
	Label   string
	Pairs   []CommandPair
	Start   time.Time
	End     time.Time
	Targets []string
}

func ClusterPairs(pairs []CommandPair, gapThreshold time.Duration) []Phase {
	if len(pairs) == 0 {
		return nil
	}
	if gapThreshold <= 0 {
		gapThreshold = 5 * time.Minute
	}

	var phases []Phase
	phaseLabel := 1
	currentTargets := make(map[string]struct{})
	current := Phase{
		Label: fmt.Sprintf("Phase %d", phaseLabel),
		Start: pairs[0].Timestamp,
		End:   pairs[0].Timestamp,
		Pairs: []CommandPair{pairs[0]},
	}
	for _, tgt := range pairs[0].Targets {
		currentTargets[tgt] = struct{}{}
	}

	for _, pair := range pairs[1:] {
		gap := pair.Timestamp.Sub(current.End)
		newHost := hasNewTarget(pair.Targets, currentTargets)
		if gap > gapThreshold || newHost {
			current.Targets = targetsFromSet(currentTargets)
			phases = append(phases, current)

			phaseLabel++
			current = Phase{
				Label: fmt.Sprintf("Phase %d", phaseLabel),
				Start: pair.Timestamp,
				End:   pair.Timestamp,
				Pairs: []CommandPair{pair},
			}
			currentTargets = make(map[string]struct{})
			for _, tgt := range pair.Targets {
				currentTargets[tgt] = struct{}{}
			}
			continue
		}

		current.Pairs = append(current.Pairs, pair)
		if pair.Timestamp.After(current.End) {
			current.End = pair.Timestamp
		}
		for _, tgt := range pair.Targets {
			currentTargets[tgt] = struct{}{}
		}
	}

	current.Targets = targetsFromSet(currentTargets)
	phases = append(phases, current)
	return phases
}

func hasNewTarget(targets []string, seen map[string]struct{}) bool {
	for _, tgt := range targets {
		if _, ok := seen[tgt]; !ok {
			return true
		}
	}
	return false
}

func targetsFromSet(set map[string]struct{}) []string {
	if len(set) == 0 {
		return nil
	}
	out := make([]string, 0, len(set))
	for tgt := range set {
		out = append(out, tgt)
	}
	sort.Strings(out)
	return out
}
