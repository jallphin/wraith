package config

import (
	"encoding/json"
	"os"
	"path/filepath"

	"github.com/BurntSushi/toml"
)

type Config struct {
	Engagement EngagementConfig `toml:"engagement"`
	Operator   OperatorConfig   `toml:"operator"`
	AI         AIConfig         `toml:"ai"`
}

type EngagementConfig struct {
	ID        string   `toml:"id"`
	Client    string   `toml:"client"`
	StartDate string   `toml:"start_date"`
	EndDate   string   `toml:"end_date"`
	Scope     []string `toml:"scope"`
}

type OperatorConfig struct {
	Name string `toml:"name"`
	Box  string `toml:"box"` // defaults to hostname if empty
}

type AIConfig struct {
	AnthropicKey string `toml:"anthropic_key"`
	OpenAIKey    string `toml:"openai_key"`
	Model        string `toml:"model"` // optional override
}

// Load reads ~/.wraith/config.toml. Returns empty config (not error) if file doesn't exist.
func Load() (Config, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return Config{}, err
	}
	path := filepath.Join(home, ".wraith", "config.toml")
	var cfg Config
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return cfg, nil // no config file is fine
	}
	if _, err := toml.DecodeFile(path, &cfg); err != nil {
		return cfg, err
	}
	// If operator.box is empty, default to hostname
	if cfg.Operator.Box == "" {
		if h, err := os.Hostname(); err == nil {
			cfg.Operator.Box = h
		}
	}
	return cfg, nil
}

// ReadOpenAICodexToken reads the current OpenAI Codex OAuth access token from
// openclaw's auth-profiles.json. Returns empty string if not found.
func ReadOpenAICodexToken() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	path := filepath.Join(home, ".openclaw", "agents", "main", "agent", "auth-profiles.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var doc struct {
		Profiles map[string]struct {
			Access string `json:"access"`
		} `json:"profiles"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		return ""
	}
	if p, ok := doc.Profiles["openai-codex:default"]; ok {
		return p.Access
	}
	return ""
}

// WriteExample writes a commented example config to ~/.wraith/config.toml
// if it doesn't already exist.
func WriteExample() error {
	home, err := os.UserHomeDir()
	if err != nil {
		return err
	}
	dir := filepath.Join(home, ".wraith")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	path := filepath.Join(dir, "config.toml")
	if _, err := os.Stat(path); err == nil {
		return nil // already exists
	}
	example := `# wraith configuration
# Edit this file to set your engagement and operator details.

[engagement]
id = ""           # Unique engagement ID (shared across operators on same engagement)
client = ""       # Client name
start_date = ""   # YYYY-MM-DD
end_date = ""     # YYYY-MM-DD
scope = []        # e.g. ["10.10.10.0/24", "*.example.com"]

[operator]
name = ""         # Your operator handle
# box = ""        # Defaults to hostname

[ai]
# model = ""           # Optional model override (e.g. "gpt-4.1", "gpt-5.2", "claude-sonnet-4-5")
# anthropic_key = ""   # Falls back to ANTHROPIC_API_KEY env var
# openai_key = ""      # Falls back to OPENAI_API_KEY env var
# If neither is set, wraith will try openclaw's OpenAI Codex OAuth token automatically.
`
	return os.WriteFile(path, []byte(example), 0600)
}
