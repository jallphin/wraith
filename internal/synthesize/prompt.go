package synthesize

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/jallphin/wraith/internal/store"
)

func BuildPrompt(phases []Phase, sessionID string) string {
	var b strings.Builder
	b.WriteString(`You are analyzing a red team engagement session. The operator's commands and outputs
are grouped into phases below. Identify security findings.

Return a JSON array of findings matching this exact schema:
[{"title": "string", "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO", "asset": "string (hostname/IP or description)", "technique": "string (MITRE ATT&CK ID and name if applicable)", "phase": "string (Reconnaissance|Initial Access|Execution|Persistence|Privilege Escalation|Lateral Movement|Collection|Exfiltration|Impact|Other)", "narrative": "string (2-4 sentences describing the finding)"}]

Only include genuine security findings. If nothing notable, return [].

`)
	b.WriteString(fmt.Sprintf("Session ID: %s\n", sessionID))

	for _, phase := range phases {
		start := "--"
		end := "--"
		if !phase.Start.IsZero() {
			start = phase.Start.Format("15:04")
		}
		if !phase.End.IsZero() {
			end = phase.End.Format("15:04")
		}
		b.WriteString(fmt.Sprintf("\n--- %s (%s - %s) ---\n", phase.Label, start, end))
		if len(phase.Targets) > 0 {
			b.WriteString("Targets: ")
			b.WriteString(strings.Join(phase.Targets, ", "))
			b.WriteByte('\n')
		} else {
			b.WriteString("Targets: none\n")
		}
		for _, pair := range phase.Pairs {
			b.WriteString("$ ")
			b.WriteString(pair.Command)
			b.WriteByte('\n')
			if pair.Output != "" {
				b.WriteString(pair.Output)
				if !strings.HasSuffix(pair.Output, "\n") {
					b.WriteByte('\n')
				}
				b.WriteByte('\n')
			} else {
				b.WriteByte('\n')
			}
		}
	}

	return strings.TrimSpace(b.String()) + "\n"
}

func CallAI(prompt string) (string, error) {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return callAnthropic(prompt, key)
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return callOpenAI(prompt, key)
	}
	return "", fmt.Errorf("no AI API key configured")
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Completion string `json:"completion"`
}

func callAnthropic(prompt, key string) (string, error) {
	payload := anthropicRequest{
		Model:     "claude-sonnet-4-5",
		MaxTokens: 2048,
		Messages:  []anthropicMessage{{Role: "user", Content: prompt}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.anthropic.com/v1/messages", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", key)
	req.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("anthropic API error: %s", strings.TrimSpace(string(body)))
	}

	var out anthropicResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	return out.Completion, nil
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	Messages  []openAIMessage `json:"messages"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

func callOpenAI(prompt, key string) (string, error) {
	payload := openAIRequest{
		Model:     "gpt-4.1",
		MaxTokens: 2048,
		Messages:  []openAIMessage{{Role: "user", Content: prompt}},
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequest("POST", "https://api.openai.com/v1/chat/completions", bytes.NewReader(data))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", fmt.Sprintf("Bearer %s", key))

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("openai API error: %s", strings.TrimSpace(string(body)))
	}

	var out openAIResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return "", err
	}
	if len(out.Choices) == 0 {
		return "", errors.New("openai API returned no choices")
	}
	return out.Choices[0].Message.Content, nil
}

func ParseFindings(response, sessionID string) ([]store.Finding, error) {
	jsonBlob, err := extractJSONArray(response)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		Title     string `json:"title"`
		Severity  string `json:"severity"`
		Asset     string `json:"asset"`
		Technique string `json:"technique"`
		Phase     string `json:"phase"`
		Narrative string `json:"narrative"`
	}
	if err := json.Unmarshal([]byte(jsonBlob), &entries); err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	var findings []store.Finding
	for _, entry := range entries {
		if entry.Title == "" {
			continue
		}
		finding := store.Finding{
			ID:        uuid.NewString(),
			SessionID: sessionID,
			Title:     entry.Title,
			Severity:  parseSeverity(entry.Severity),
			Asset:     entry.Asset,
			Technique: entry.Technique,
			Phase:     parsePhase(entry.Phase),
			Narrative: entry.Narrative,
			Status:    store.StatusProposed,
			CreatedAt: now,
			UpdatedAt: now,
		}
		findings = append(findings, finding)
	}
	return findings, nil
}

func extractJSONArray(raw string) (string, error) {
	start := strings.Index(raw, "[")
	end := strings.LastIndex(raw, "]")
	if start == -1 || end == -1 || start >= end {
		return "", errors.New("no JSON array found in AI response")
	}
	snippet := strings.TrimSpace(raw[start : end+1])
	return snippet, nil
}

func parseSeverity(value string) store.Severity {
	switch strings.ToUpper(strings.TrimSpace(value)) {
	case "CRITICAL":
		return store.SeverityCritical
	case "HIGH":
		return store.SeverityHigh
	case "MEDIUM":
		return store.SeverityMedium
	case "LOW":
		return store.SeverityLow
	case "INFO":
		return store.SeverityInfo
	default:
		return store.SeverityInfo
	}
}

func parsePhase(value string) store.Phase {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "reconnaissance":
		return store.PhaseRecon
	case "initial access":
		return store.PhaseInitialAccess
	case "execution":
		return store.PhaseExecution
	case "persistence":
		return store.PhasePersistence
	case "privilege escalation":
		return store.PhasePrivEsc
	case "lateral movement":
		return store.PhaseLatMov
	case "collection":
		return store.PhaseCollection
	case "exfiltration":
		return store.PhaseExfil
	case "impact":
		return store.PhaseImpact
	default:
		return store.PhaseOther
	}
}
