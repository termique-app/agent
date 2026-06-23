package config

import (
	"errors"
	"fmt"
	"net/url"
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
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}
	// The config holds a plaintext bearer token. Refuse to run if it is
	// group- or world-readable — a permissive config is a token-leak vector.
	if info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf("config: %s has insecure permissions %#o; run: chmod 600 %s", path, info.Mode().Perm(), path)
	}

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

	// Enforce HTTPS — the token is sent as a Bearer header. A tampered config
	// pointing at http:// would leak the token in cleartext.
	u, err := url.Parse(cfg.APIURL)
	if err != nil || u.Scheme != "https" || u.Host == "" {
		return nil, errors.New("config: api_url must be a valid https:// URL")
	}

	return &cfg, nil
}
