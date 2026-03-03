package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/jallphin/wraith/internal/capture"
	"github.com/jallphin/wraith/internal/store"
	"github.com/jallphin/wraith/internal/synthesize"
	"github.com/jallphin/wraith/internal/tui"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "wraith: cannot determine home dir: %v\n", err)
		os.Exit(1)
	}

	sessionDir := filepath.Join(home, ".wraith", "sessions")
	if err := os.MkdirAll(sessionDir, 0700); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: cannot create session dir: %v\n", err)
		os.Exit(1)
	}

	args := os.Args[1:]
	if len(args) > 0 {
		switch args[0] {
		case "list":
			if err := cmdList(sessionDir); err != nil {
				fmt.Fprintf(os.Stderr, "wraith list: %v\n", err)
				os.Exit(1)
			}
			return
		case "review":
			id := ""
			if len(args) > 1 {
				id = args[1]
			}
			if err := cmdReview(sessionDir, id); err != nil {
				fmt.Fprintf(os.Stderr, "wraith review: %v\n", err)
				os.Exit(1)
			}
			return
		default:
			// fallthrough to capture mode, passing args through to shell
		}
	}

	if err := cmdCapture(sessionDir, args); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: %v\n", err)
		os.Exit(1)
	}
}

func cmdCapture(sessionDir string, shellArgs []string) error {
	db, sessionID, err := store.NewSession(sessionDir)
	if err != nil {
		return fmt.Errorf("cannot initialize store: %w", err)
	}
	defer db.Close()

	fmt.Fprintf(os.Stderr, "\033[2m[wraith] session %s — capturing\033[0m\n", sessionID)

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell, shellArgs...)
	if err := capture.Run(cmd, db); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: session ended: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\033[2m[wraith] session %s — complete\033[0m\n", sessionID)
	return nil
}

func cmdList(sessionDir string) error {
	sessions, err := store.ListSessions(sessionDir)
	if err != nil {
		return err
	}
	if len(sessions) == 0 {
		fmt.Println("no sessions")
		return nil
	}

	for _, s := range sessions {
		id := s.ID
		if len(id) > 8 {
			id = id[:8]
		}
		start := s.Start.Local().Format("2006-01-02 15:04:05")
		dur := s.Duration.Truncate(1e9).String()
		fmt.Printf("%s\t%s\t%s\t%d events\t%d findings\n", id, start, dur, s.EventCount, s.FindingCount)
	}
	return nil
}

func cmdReview(sessionDir, id string) error {
	var meta store.SessionMeta
	var err error

	if id == "" {
		meta, err = store.MostRecentSession(sessionDir)
		if err != nil {
			return err
		}
	} else {
		// accept short id prefix
		sessions, err := store.ListSessions(sessionDir)
		if err != nil {
			return err
		}
		for _, s := range sessions {
			if s.ID == id || strings.HasPrefix(s.ID, id) {
				meta = s
				break
			}
		}
		if meta.Path == "" {
			return fmt.Errorf("session not found: %s", id)
		}
	}

	db, err := store.OpenSession(meta.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	findings, err := db.LoadFindings(db.SessionID)
	if err != nil {
		return err
	}
	if len(findings) == 0 {
		findings, err = synthesize.Run(db)
		if err != nil {
			return err
		}
		for _, f := range findings {
			_ = db.SaveFinding(f)
		}
	}

	// refresh meta counts
	meta.ID = db.SessionID
	meta.FindingCount = len(findings)
	return tui.Run(db, meta, findings)
}
