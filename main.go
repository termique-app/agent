package main

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/termique-app/agent/internal/client"
	"github.com/termique-app/agent/internal/config"
	"github.com/termique-app/agent/internal/metrics"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

func main() {
	// --version must short-circuit before config.Load runs: config.Load
	// requires an existing 0600 config.toml, but the update script (and
	// anyone checking a fresh install) needs to run this with zero config
	// present. Print only the bare semver string, nothing else.
	if len(os.Args) > 1 && os.Args[1] == "--version" {
		fmt.Println(version)
		os.Exit(0)
	}

	log.SetFlags(log.Ldate | log.Ltime)
	log.Printf("termique-agent %s starting", version)

	cfgPath := configPath()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		log.Fatalf("failed to load config from %s: %v", cfgPath, err)
	}

	if cfg.Debug {
		log.Printf("debug: config loaded — server_id=%s api_url=%s interval=%ds",
			cfg.ServerID, cfg.APIURL, cfg.Interval)
	}

	c := client.New(cfg.APIURL, cfg.Token, cfg.ServerID)
	interval := time.Duration(cfg.Interval) * time.Second

	// Collect once immediately on startup, then on the ticker.
	collect(c, cfg, interval)

	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			collect(c, cfg, interval)
		case sig := <-quit:
			log.Printf("received %s, shutting down", sig)
			return
		}
	}
}

// collect gathers a snapshot and ships it to the API.
func collect(c *client.Client, cfg *config.Config, interval time.Duration) {
	snap, err := metrics.Collect(interval)
	if err != nil {
		log.Printf("error collecting metrics: %v", err)
		return
	}

	if cfg.Debug {
		log.Printf("debug: snapshot — cpu=%.2f%% ram=%.2f%% disk=%.2f%%",
			snap.CpuPercent, snap.RamPercent, snap.DiskPercent)
	}

	if err := c.Send(snap); err != nil {
		log.Printf("error sending metrics: %v", err)
		return
	}

	log.Printf("metrics sent — cpu=%.2f%% ram=%.2f%% disk=%.2f%%",
		snap.CpuPercent, snap.RamPercent, snap.DiskPercent)
}

// configPath returns the config file path from TERMIQUE_CONFIG env var,
// or falls back to ~/.config/termique-agent/config.toml.
func configPath() string {
	if p := os.Getenv("TERMIQUE_CONFIG"); p != "" {
		return p
	}
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("cannot determine home directory: %v", err)
	}
	return filepath.Join(home, ".config", "termique-agent", "config.toml")
}
