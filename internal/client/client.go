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

// Send POSTs the snapshot to /api/monitoring/ingest.
// The token is never included in log output.
func (c *Client) Send(snap *metrics.Snapshot) error {
	body, err := json.Marshal(snap)
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
