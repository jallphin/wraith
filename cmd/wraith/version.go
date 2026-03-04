package main

const Version = "0.2.0"

// GitCommit is injected at build time via -ldflags.
// Build with: go build -ldflags "-X main.GitCommit=$(git rev-parse --short HEAD)"
var GitCommit = "dev"
