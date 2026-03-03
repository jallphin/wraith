package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/jallphin/wraith/internal/capture"
	"github.com/jallphin/wraith/internal/store"
)

func main() {
	// Determine session DB path: ~/.wraith/sessions/<timestamp>.db
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

	db, sessionID, err := store.NewSession(sessionDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "wraith: cannot initialize store: %v\n", err)
		os.Exit(1)
	}
	defer db.Close()

	fmt.Fprintf(os.Stderr, "\033[2m[wraith] session %s — capturing\033[0m\n", sessionID)

	// Determine shell to wrap
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/bash"
	}

	// Pass-through any args after -- to the shell
	shellArgs := os.Args[1:]

	cmd := exec.Command(shell, shellArgs...)
	if err := capture.Run(cmd, db); err != nil {
		fmt.Fprintf(os.Stderr, "wraith: session ended: %v\n", err)
	}

	fmt.Fprintf(os.Stderr, "\033[2m[wraith] session %s — complete\033[0m\n", sessionID)
}
