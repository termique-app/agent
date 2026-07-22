package client

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/termique-app/agent/internal/metrics"
	"github.com/termique-app/agent/internal/security"
)

const requestTimeout = 10 * time.Second
const maxBodyLog = 200

// Client sends metric snapshots to the Termique API.
type Client struct {
	apiURL   string
	token    string
	serverID string
	http     *http.Client
}

// New creates a Client configured for the given API URL, token, and server ID.
func New(apiURL, token, serverID string) *Client {
	return &Client{
		apiURL:   apiURL,
		token:    token,
		serverID: serverID,
		http:     &http.Client{Timeout: requestTimeout},
	}
}

// ingestPayload is the JSON body posted to /api/monitoring/ingest. It embeds
// Snapshot by pointer so its fields marshal flattened (unchanged wire shape
// for agents that never report security sources), plus an optional
// SecuritySources field (FR-4.3/D-6).
//
// SecuritySources is a POINTER to a slice, not a bare slice, so `omitempty`
// only triggers on a nil pointer — a non-nil pointer to an EMPTY slice still
// marshals as `"security_sources":[]`. This distinction is load-bearing:
//   - nil pointer            -> field omitted entirely (capture disabled, or
//     an older agent that never populates this field at all).
//   - pointer to []           -> capture enabled, zero sources detected — the
//     silent-misconfiguration case FR-4.3 exists to surface.
//   - pointer to [...]        -> capture enabled, N sources actively tailed.
type ingestPayload struct {
	*metrics.Snapshot
	SecuritySources *[]security.SourceStatus `json:"security_sources,omitempty"`
}

// Send POSTs the snapshot (plus optional detected security-source status,
// FR-4.3/D-6) to /api/monitoring/ingest. Pass nil for securitySources when
// security-event capture is disabled — the field is then omitted from the
// wire body entirely, matching the exact pre-existing payload shape. The
// token is never included in log output.
func (c *Client) Send(snap *metrics.Snapshot, securitySources *[]security.SourceStatus) error {
	body, err := json.Marshal(ingestPayload{Snapshot: snap, SecuritySources: securitySources})
	if err != nil {
		return fmt.Errorf("client: marshal: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.apiURL+"/api/monitoring/ingest", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: build request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Server-ID", c.serverID)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyLog))
		return fmt.Errorf("client: non-2xx response %d: %s", resp.StatusCode, truncate(string(raw), maxBodyLog))
	}

	return nil
}

// PushSecurityEvents POSTs a batch of security events to
// /api/monitoring/security-events, reusing the same Bearer-token/timeout
// plumbing as Send (FR-1.6) — no new credential type on the agent. The
// bearer token is never included in log output, mirroring Send's existing
// token-safety behavior.
func (c *Client) PushSecurityEvents(batch []security.Event) error {
	if len(batch) == 0 {
		return nil
	}

	body, err := json.Marshal(struct {
		Events []security.Event `json:"events"`
	}{Events: batch})
	if err != nil {
		return fmt.Errorf("client: marshal security events: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, c.apiURL+"/api/monitoring/security-events", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("client: build security events request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("X-Server-ID", c.serverID)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("client: security events request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBodyLog))
		return fmt.Errorf("client: security events non-2xx response %d: %s", resp.StatusCode, truncate(string(raw), maxBodyLog))
	}

	return nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
