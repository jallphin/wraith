package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/jallphin/wraith/internal/capture"
	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
	"github.com/jallphin/wraith/internal/tui"
)

var (
	bannerArt = strings.TrimSpace(`
█░█░█ █▀█ ▄▀█ █ ▀█▀ █░█
▀▄▀▄▀ █▀▄ █▀█ █ ░█░ █▀█
`)
	bannerStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("250")).
			Bold(true)
	taglineStyle = lipgloss.NewStyle().
			Foreground(lipgloss.Color("241"))
	sessionStatusStyle = lipgloss.NewStyle().
				Foreground(lipgloss.Color("70"))
)

func main() {
	printBanner()

	_ = config.WriteExample()
	cfg, _ := config.Load()

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
			if err := cmdReview(sessionDir, id, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "wraith review: %v\n", err)
				os.Exit(1)
			}
			return
		case "note":
			if len(args) < 2 {
				fmt.Fprintln(os.Stderr, "usage: wraith note <text>")
				os.Exit(1)
			}
			if err := cmdNote(sessionDir, strings.Join(args[1:], " "), cfg); err != nil {
				fmt.Fprintf(os.Stderr, "wraith note: %v\n", err)
				os.Exit(1)
			}
			return
		case "resyn":
			id := ""
			if len(args) > 1 {
				id = args[1]
			}
			if err := cmdResyn(sessionDir, id, cfg); err != nil {
				fmt.Fprintf(os.Stderr, "wraith resyn: %v\n", err)
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

	fmt.Fprintln(os.Stderr, sessionStatusStyle.Render(fmt.Sprintf("[wraith] session %s — capturing", sessionID)))

	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	cmd := exec.Command(shell, shellArgs...)
	if err := capture.Run(cmd, db); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: session ended: %v\n", err)
	}

	fmt.Fprintln(os.Stderr, sessionStatusStyle.Render(fmt.Sprintf("[wraith] session %s — complete", sessionID)))
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

func cmdReview(sessionDir, id string, cfg config.Config) error {
	meta, err := store.FindSession(sessionDir, id)
	if err != nil {
		return err
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
		findings, err = tui.RunSynthesisWithSpinner(db, cfg)
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
	return tui.Run(db, meta, findings, cfg)
}

func cmdResyn(sessionDir, id string, cfg config.Config) error {
	meta, err := store.FindSession(sessionDir, id)
	if err != nil {
		return err
	}

	db, err := store.OpenSession(meta.Path)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := db.DeleteFindings(); err != nil {
		return err
	}
	if err := db.DeleteNoteEvents(); err != nil {
		return err
	}

	shortID := meta.ID
	if len(shortID) > 8 {
		shortID = shortID[:8]
	}
	fmt.Fprintf(os.Stderr, "[wraith] re-synthesizing session %s...\n", shortID)
	findings, err := tui.RunSynthesisWithSpinner(db, cfg)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "[wraith] %d findings generated\n", len(findings))
	return nil
}

func cmdNote(sessionDir, text string, cfg config.Config) error {
	meta, err := store.MostRecentSession(sessionDir)
	if err != nil {
		return err
	}
	db, err := store.OpenSession(meta.Path)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.WriteEvent(store.Event{
		Kind:      store.EventNote,
		Timestamp: time.Now(),
		Note:      text,
	}); err != nil {
		return err
	}
	fmt.Printf("[wraith] note saved to session %s\n", meta.ID[:8])
	return nil
}

func printBanner() {
	fmt.Fprintln(os.Stderr, bannerStyle.Render(bannerArt))
	fmt.Fprintln(os.Stderr, taglineStyle.Render(fmt.Sprintf("  red team session intelligence  v%s", Version)))
	fmt.Fprintln(os.Stderr)
}
