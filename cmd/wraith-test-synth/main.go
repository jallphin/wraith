// Quick test harness: run synthesis against an existing session DB and print findings.
package main

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
	"github.com/jallphin/wraith/internal/synthesize"
)

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: wraith-test-synth <path-to-session.db> [--debug]")
		os.Exit(1)
	}

	debug := len(os.Args) > 2 && os.Args[2] == "--debug"

	db, err := store.OpenSession(os.Args[1])
	if err != nil {
		fmt.Fprintf(os.Stderr, "open: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	if debug {
		events, err := synthesize.LoadEvents(db)
		if err != nil {
			fmt.Fprintf(os.Stderr, "load events: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("events: %d\n", len(events))
		outCount := 0
		for _, e := range events {
			if e.Kind == store.EventOutput {
				outCount++
			}
		}
		fmt.Printf("output events: %d\n", outCount)

		pairs := synthesize.ExtractCommandPairs(events)
		fmt.Printf("command pairs: %d\n", len(pairs))
		for i, p := range pairs {
			fmt.Printf("\n--- pair %d ---\n", i+1)
			fmt.Printf("command: %q\n", p.Command)
			fmt.Printf("output (%d chars): %q\n", len(p.Output), truncStr(p.Output, 200))
			fmt.Printf("targets: %v\n", p.Targets)
			fmt.Printf("ts: %v\n", p.Timestamp)
		}
		return
	}

	findings, err := synthesize.Run(db, config.Config{})
	if err != nil {
		fmt.Fprintf(os.Stderr, "synthesize: %v\n", err)
		os.Exit(1)
	}

	if len(findings) == 0 {
		fmt.Println("no findings")
		return
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	enc.Encode(findings)
}

func truncStr(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
