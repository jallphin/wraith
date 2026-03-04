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
	"github.com/jallphin/wraith/internal/config"
	"github.com/jallphin/wraith/internal/store"
)

func BuildPrompt(phases []Phase, sessionID string, cfg config.Config) string {
	var b strings.Builder
	b.WriteString(`You are analyzing a red team engagement session. The operator's commands and outputs
are grouped into phases below. Identify security findings.

Return a JSON array of findings matching this exact schema:
[{
  "title": "string",
  "severity": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "asset": "string",
  "technique": "string (MITRE ATT&CK ID and name)",
  "phase": "string",
  "narrative": "string (2-4 sentences)",
  "cve": "string or null (CVE ID if a known CVE applies, otherwise null)",
  "cvss_score": "number or null (CVSS 3.1 base score 0.0-10.0)",
  "cvss_vector": "string or null (full CVSS 3.1 vector string)",
  "cwe": "string or null (most applicable CWE ID, e.g. CWE-269)",
  "cpe": "string or null (CPE 2.3 for the vulnerable component if known)",
  "tags": ["array", "of", "short", "lowercase", "tags"],
  "cmd_refs": [1, 2]
}]

For misconfigurations with no known CVE, set cve and cpe to null but always populate cwe. Tags should be short lowercase descriptors like: privesc, weak-creds, idor, rce, lfi, misconfiguration, exposed-service, capabilities.

Include a 'cmd_refs' array that lists the [cmd:N] indices of the commands that directly support each finding. Only include genuine security findings. If nothing notable, return [].

`)
	if cfg.Engagement.ID != "" {
		b.WriteString(fmt.Sprintf("Engagement: %s | Client: %s | Scope: %s\n\n", cfg.Engagement.ID, cfg.Engagement.Client, strings.Join(cfg.Engagement.Scope, ", ")))
	}
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
			b.WriteString(fmt.Sprintf("[cmd:%d] $ %s\n", pair.Index, pair.Command))
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

func CallAI(prompt string, cfg config.Config) (string, error) {
	if key := strings.TrimSpace(cfg.AI.AnthropicKey); key != "" {
		return callAnthropic(prompt, key, "claude-sonnet-4-5")
	}
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return callAnthropic(prompt, key, "claude-sonnet-4-5")
	}
	if key := strings.TrimSpace(cfg.AI.OpenAIKey); key != "" {
		return callOpenAI(prompt, key, "gpt-4.1")
	}
	if key := os.Getenv("OPENAI_API_KEY"); key != "" {
		return callOpenAI(prompt, key, "gpt-4.1")
	}
	return "", fmt.Errorf("no AI API key configured")
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicRequest struct {
	Model       string             `json:"model"`
	MaxTokens   int                `json:"max_tokens"`
	Temperature float64            `json:"temperature"`
	Messages    []anthropicMessage `json:"messages"`
}

type anthropicResponse struct {
	Completion string `json:"completion"` // legacy completions API
	Content    []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"` // messages API
}

func callAnthropic(prompt, key, model string) (string, error) {
	payload := anthropicRequest{
		Model:       model,
		MaxTokens:   2048,
		Temperature: 0,
		Messages:    []anthropicMessage{{Role: "user", Content: prompt}},
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
	// Messages API returns content array; fall back to legacy completion field.
	for _, c := range out.Content {
		if c.Type == "text" && c.Text != "" {
			return c.Text, nil
		}
	}
	return out.Completion, nil
}

type openAIMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openAIRequest struct {
	Model       string          `json:"model"`
	MaxTokens   int             `json:"max_tokens"`
	Temperature float64         `json:"temperature"`
	Messages    []openAIMessage `json:"messages"`
}

type openAIResponse struct {
	Choices []struct {
		Message openAIMessage `json:"message"`
	} `json:"choices"`
}

func callOpenAI(prompt, key, model string) (string, error) {
	payload := openAIRequest{
		Model:       model,
		MaxTokens:   2048,
		Temperature: 0,
		Messages:    []openAIMessage{{Role: "user", Content: prompt}},
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

func ParseFindings(response, sessionID string, pairRowIDs []int64) ([]store.Finding, error) {
	jsonBlob, err := extractJSONArray(response)
	if err != nil {
		return nil, err
	}

	var entries []struct {
		Title      string   `json:"title"`
		Severity   string   `json:"severity"`
		Asset      string   `json:"asset"`
		Technique  string   `json:"technique"`
		Phase      string   `json:"phase"`
		Narrative  string   `json:"narrative"`
		CVE        *string  `json:"cve"`
		CVSSScore  *float64 `json:"cvss_score"`
		CVSSVector *string  `json:"cvss_vector"`
		CWE        *string  `json:"cwe"`
		CPE        *string  `json:"cpe"`
		Tags       []string `json:"tags"`
		CmdRefs    []int    `json:"cmd_refs"`
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
			Tags:      entry.Tags,
			Status:    store.StatusProposed,
			CreatedAt: now,
			UpdatedAt: now,
		}
		if entry.CVE != nil {
			finding.CVE = *entry.CVE
		}
		if entry.CVSSScore != nil {
			finding.CVSSScore = *entry.CVSSScore
		}
		if entry.CVSSVector != nil {
			finding.CVSSVector = *entry.CVSSVector
		}
		if entry.CWE != nil {
			finding.CWE = *entry.CWE
		}
		if entry.CPE != nil {
			finding.CPE = *entry.CPE
		}
		for _, ref := range entry.CmdRefs {
			idx := ref - 1 // cmd_refs are 1-based
			if idx < 0 || idx >= len(pairRowIDs) || pairRowIDs[idx] == 0 {
				continue
			}
			finding.EventIDs = append(finding.EventIDs, pairRowIDs[idx])
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
