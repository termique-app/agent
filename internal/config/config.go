package config

import (
	"errors"
	"os"

	"github.com/pelletier/go-toml/v2"
)

const defaultAPIURL = "https://api-app.termique.app"
const defaultInterval = 30

// Config holds all agent configuration loaded from the TOML file.
type Config struct {
	Token    string `toml:"token"`
	ServerID string `toml:"server_id"`
	APIURL   string `toml:"api_url"`
	Interval int    `toml:"interval"`
	Debug    bool   `toml:"debug"`
}

// Load reads the TOML file at path, validates required fields, and applies defaults.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := toml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Token == "" {
		return nil, errors.New("config: token is required")
	}
	if cfg.ServerID == "" {
		return nil, errors.New("config: server_id is required")
	}

	if cfg.APIURL == "" {
		cfg.APIURL = defaultAPIURL
	}
	if cfg.Interval <= 0 {
		cfg.Interval = defaultInterval
	}

	return &cfg, nil
}
