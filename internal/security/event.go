package security

import "time"

// EventType enumerates the fixed v1 matcher set (FR-1.4). This set is
// deliberately small and fixed — v1 does not support custom patterns.
type EventType string

const (
	EventSSHAuthFail        EventType = "ssh_auth_fail"
	EventSSHAuthSuccess     EventType = "ssh_auth_success"
	EventFail2banBan        EventType = "fail2ban_ban"
	EventFail2banUnban      EventType = "fail2ban_unban"
	EventHTTPErrorSpike     EventType = "http_error_spike"
	EventHTTPPathBruteForce EventType = "http_path_brute_force"
)

// Event is a single structured security event. Only the fields relevant to
// Type are populated (see the per-field comments below); the rest are
// omitted from JSON via omitempty. Matchers never emit a raw log line —
// only these fixed structured shapes (FR-1.4/NFR-5).
type Event struct {
	Type EventType `json:"type"`
	Ts   time.Time `json:"ts"`

	// ssh_auth_fail / ssh_auth_success / http_error_spike / http_path_brute_force
	SourceIP string `json:"source_ip,omitempty"`

	// ssh_auth_fail / ssh_auth_success
	Username string `json:"username,omitempty"`

	// fail2ban_ban / fail2ban_unban
	IP   string `json:"ip,omitempty"`
	Jail string `json:"jail,omitempty"`

	// http_error_spike / http_path_brute_force
	WindowStart time.Time `json:"window_start,omitempty"`
	Count       int       `json:"count,omitempty"`

	// http_error_spike only
	StatusClass string `json:"status_class,omitempty"`

	// http_path_brute_force only — request path with query string stripped,
	// so randomized query params (nonces, etc.) don't split one attack
	// across many distinct counters.
	Path string `json:"path,omitempty"`
}
