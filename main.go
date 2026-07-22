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
	"github.com/termique-app/agent/internal/security"
)

// version is injected at build time via -ldflags "-X main.version=<tag>".
var version = "dev"

// securityTailPollInterval is the security-event log-tail poll cadence —
// deliberately short, distinct from BOTH the 30s metrics tick and the
// (much longer, default 120s) security flush interval. It needs to be short
// enough to catch http_error_spike's rolling 1-minute window promptly (a
// spike that starts and ends between two widely-spaced polls could be
// under-counted). Not exposed via config in v1 — ship a reasonable starting
// constant, tune later (per the task doc's own note that this is an open,
// non-blocking tunable).
const securityTailPollInterval = 15 * time.Second

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

	// Security-event capture (opt-in, FR-1.1). When disabled (the default),
	// secTailC/secFlushC stay nil — a nil channel blocks forever in a
	// select, so those cases never fire and no ticker/goroutine/file handle
	// is ever allocated for this feature (T1.2/T1.4 AC: zero I/O when off).
	var secState *security.State
	var secSources []security.Source
	var secSpikes *security.SpikeAggregator
	var secPathSpikes *security.PathSpikeAggregator
	var secBuffer *security.Buffer
	var secTailC <-chan time.Time
	var secFlushC <-chan time.Time

	if cfg.SecurityEventsEnabled {
		var err error
		secState, err = security.LoadState(securityStatePath())
		if err != nil {
			log.Printf("security: failed to load tailing state, starting fresh: %v", err)
			secState = &security.State{Sources: map[string]security.SourceState{}}
		}
		secSources = security.DetectSources(cfg.ReverseProxyLogPath)
		secSpikes = security.NewSpikeAggregator(security.DefaultHTTPErrorSpikeThreshold)
		secPathSpikes = security.NewPathSpikeAggregator(security.DefaultPathBruteForceThreshold)
		secBuffer = security.NewBuffer(cfg.SecurityEventsMaxBatch)

		secTailTicker := time.NewTicker(securityTailPollInterval)
		defer secTailTicker.Stop()
		secFlushTicker := time.NewTicker(time.Duration(cfg.SecurityEventsFlushIntervalSecs) * time.Second)
		defer secFlushTicker.Stop()
		secTailC = secTailTicker.C
		secFlushC = secFlushTicker.C

		log.Printf("security: event capture enabled — %d source(s) detected", len(secSources))
	}

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	for {
		select {
		case <-ticker.C:
			collect(c, cfg, interval)
		case <-secTailC:
			pollSecuritySources(secSources, secState, secSpikes, secPathSpikes, secBuffer)
		case <-secFlushC:
			flushSecurityEvents(c, secBuffer)
		case sig := <-quit:
			log.Printf("received %s, shutting down", sig)
			return
		}
	}
}

// securityStatePath returns the path for the security-event tailing offset
// state file. Prefers systemd's $STATE_DIRECTORY (set automatically when the
// unit declares StateDirectory=termique-agent, resolving to
// /var/lib/termique-agent — writable even under ProtectSystem=strict). Falls
// back to alongside the main config file (~/.config/termique-agent/) for
// non-systemd runs (local dev, `go run`) — note that path is READ-ONLY under
// ProtectHome=read-only, so a systemd-managed install without
// StateDirectory= set will fail to persist state (logged, non-fatal) until
// its unit file is updated.
func securityStatePath() string {
	if dir := os.Getenv("STATE_DIRECTORY"); dir != "" {
		return filepath.Join(dir, "security-state.json")
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".", ".config", "termique-agent", "security-state.json")
	}
	return filepath.Join(home, ".config", "termique-agent", "security-state.json")
}

// pollSecuritySources tails every watched source once, routes matched lines
// through the appropriate matcher, and persists the updated tailing offsets.
func pollSecuritySources(sources []security.Source, state *security.State, spikes *security.SpikeAggregator, pathSpikes *security.PathSpikeAggregator, buf *security.Buffer) {
	if state == nil || buf == nil {
		return
	}
	now := time.Now()
	for _, src := range sources {
		lines, err := security.TailNewLines(src, state)
		if err != nil {
			log.Printf("security: error tailing %s: %v", src.Path, err)
			continue
		}
		for _, line := range lines {
			if src.Name == "reverse_proxy" {
				ip, path, statusClass, ok := security.ParseAccessLine(line)
				if !ok {
					continue
				}
				// http_error_spike: 4xx/5xx only.
				if statusClass != "" {
					if ev := spikes.Observe(ip, statusClass, now); ev != nil {
						buf.Add(*ev)
					}
				}
				// http_path_brute_force: every request, regardless of status —
				// a login-form brute force typically returns 200/302.
				if ev := pathSpikes.Observe(ip, path, now); ev != nil {
					buf.Add(*ev)
				}
				continue
			}
			if ev := security.MatchLine(src.Name, line, now); ev != nil {
				buf.Add(*ev)
			}
		}
	}
	if err := state.Save(securityStatePath()); err != nil {
		log.Printf("security: failed to persist tailing state: %v", err)
	}
}

// flushSecurityEvents drains the buffer (up to the configured cap) and
// POSTs it via the client. A failed POST leaves the batch buffered for retry
// on the next flush (FR-2.5) — Buffer.Flush already handles that contract.
func flushSecurityEvents(c *client.Client, buf *security.Buffer) {
	if buf == nil {
		return
	}
	if err := buf.Flush(func(batch []security.Event) error {
		return c.PushSecurityEvents(batch)
	}); err != nil {
		log.Printf("security: flush failed, batch retained for retry: %v", err)
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
