package security

import (
	"regexp"
	"strings"
	"sync"
	"time"
)

// DefaultHTTPErrorSpikeThreshold is the default per-IP 4xx/5xx count over a
// rolling 1-minute window that triggers a single http_error_spike event
// (FR-1.4). Not currently exposed via config — v1 ships one fixed default.
const DefaultHTTPErrorSpikeThreshold = 30

// DefaultPathBruteForceThreshold is the default per-(IP, path) request count
// over a rolling 1-minute window that triggers a single
// http_path_brute_force event, regardless of response status. Complements
// http_error_spike: a login-form brute force typically returns 200/302 for
// every attempt (wrong credentials aren't an HTTP error), so status-based
// detection alone misses it entirely — this counts raw request volume to
// one path instead.
const DefaultPathBruteForceThreshold = 20

// No matcher here requires a third-party regex/parsing dependency beyond the
// Go standard library's regexp package (confirmed: go.mod has no existing
// log-parsing dependency, and none is needed for this fixed pattern set).
var (
	// sshd auth.log / secure line, e.g.:
	//   Failed password for invalid user admin from 1.2.3.4 port 51515 ssh2
	sshFailRe = regexp.MustCompile(`Failed password for (?:invalid user )?(\S+) from ([0-9a-fA-F:.]+) port \d+`)

	// Accepted password for deploy from 1.2.3.4 port 51515 ssh2
	// Accepted publickey for deploy from 1.2.3.4 port 51515 ssh2
	sshAcceptedRe = regexp.MustCompile(`Accepted (?:password|publickey) for (\S+) from ([0-9a-fA-F:.]+) port \d+`)

	// fail2ban.actions [12345]: NOTICE [sshd] Ban 1.2.3.4
	fail2banBanRe = regexp.MustCompile(`\[(\S+)\]\s+Ban\s+([0-9a-fA-F:.]+)`)
	// fail2ban.actions [12345]: NOTICE [sshd] Unban 1.2.3.4
	fail2banUnbanRe = regexp.MustCompile(`\[(\S+)\]\s+Unban\s+([0-9a-fA-F:.]+)`)

	// nginx/apache "combined" access log format:
	//   1.2.3.4 - - [22/Jul/2026:10:15:32 +0000] "GET /path HTTP/1.1" 404 512 "-" "-"
	// Captures IP, request method, request path (with query string, stripped
	// later), and status code. The HTTP-version suffix is optional and
	// uncaptured — some proxies/log configs omit it.
	accessLogRe = regexp.MustCompile(`^(\S+)\s+\S+\s+\S+\s+\[[^\]]+\]\s+"(\S+)\s+(\S+)(?:\s+\S+)?"\s+(\d{3})\s`)
)

// MatchLine inspects a single line from the named source ("auth" or
// "fail2ban") and returns a matched Event, or nil if the line matches none
// of the fixed v1 patterns. now is the match time — auth.log/fail2ban.log
// syslog-style timestamps omit the year and are ambiguous to parse reliably
// across locales/formats, so v1 deliberately uses the tail-time as ts
// (matchers run on a short poll interval, so the skew is at most a few
// seconds) rather than attempting brittle timestamp parsing.
func MatchLine(sourceName, line string, now time.Time) *Event {
	switch sourceName {
	case "auth":
		return matchAuthLine(line, now)
	case "fail2ban":
		return matchFail2banLine(line, now)
	default:
		return nil
	}
}

func matchAuthLine(line string, now time.Time) *Event {
	if m := sshFailRe.FindStringSubmatch(line); m != nil {
		return &Event{Type: EventSSHAuthFail, Ts: now, Username: m[1], SourceIP: m[2]}
	}
	if m := sshAcceptedRe.FindStringSubmatch(line); m != nil {
		return &Event{Type: EventSSHAuthSuccess, Ts: now, Username: m[1], SourceIP: m[2]}
	}
	return nil
}

func matchFail2banLine(line string, now time.Time) *Event {
	// Check Unban before Ban — both regexes are mutually exclusive by
	// construction (Ban's pattern requires whitespace immediately before
	// "Ban", which never occurs inside "Unban"), but checking Unban first
	// keeps that invariant robust to future pattern tweaks.
	if m := fail2banUnbanRe.FindStringSubmatch(line); m != nil {
		return &Event{Type: EventFail2banUnban, Ts: now, Jail: m[1], IP: m[2]}
	}
	if m := fail2banBanRe.FindStringSubmatch(line); m != nil {
		return &Event{Type: EventFail2banBan, Ts: now, Jail: m[1], IP: m[2]}
	}
	return nil
}

// ParseAccessLine extracts (ip, path, statusClass) from a combined-format
// access log line. ok is false for lines that don't match the expected
// format. Unlike the old status-only extraction, this always returns path
// and statusClass together — statusClass is "" for a 2xx/3xx response
// (never a spike candidate for http_error_spike, but still valid input for
// PathSpikeAggregator, which counts every request regardless of status: a
// login-form brute force typically returns 200/302 for every attempt).
func ParseAccessLine(line string) (ip string, path string, statusClass string, ok bool) {
	m := accessLogRe.FindStringSubmatch(line)
	if m == nil {
		return "", "", "", false
	}
	rawPath := m[3]
	if idx := strings.IndexByte(rawPath, '?'); idx >= 0 {
		rawPath = rawPath[:idx]
	}
	status := m[4]
	switch status[0] {
	case '4':
		statusClass = "4xx"
	case '5':
		statusClass = "5xx"
	}
	return m[1], rawPath, statusClass, true
}

// SpikeAggregator maintains a rolling 1-minute per-source-IP 4xx/5xx counter
// (FR-1.4). It emits exactly ONE http_error_spike event per (ip, window) when
// the count first exceeds threshold — never one event per request, per
// NFR-5's deliberate low-volume design.
type SpikeAggregator struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	byIP      map[string]*ipWindow
}

type ipWindow struct {
	windowStart time.Time
	count       int
	emitted     bool
}

// NewSpikeAggregator creates an aggregator with the given per-IP threshold
// (count must exceed this within the window to trigger). threshold <= 0
// falls back to DefaultHTTPErrorSpikeThreshold.
func NewSpikeAggregator(threshold int) *SpikeAggregator {
	if threshold <= 0 {
		threshold = DefaultHTTPErrorSpikeThreshold
	}
	return &SpikeAggregator{
		threshold: threshold,
		window:    time.Minute,
		byIP:      map[string]*ipWindow{},
	}
}

// Observe records one 4xx/5xx hit for ip at time now and returns a non-nil
// Event exactly once per rolling window when the threshold is first
// crossed — a burst of 31 requests in one minute from one IP emits exactly
// one event, not 31 (T1.3 AC).
func (a *SpikeAggregator) Observe(ip, statusClass string, now time.Time) *Event {
	a.mu.Lock()
	defer a.mu.Unlock()

	w, ok := a.byIP[ip]
	if !ok || now.Sub(w.windowStart) >= a.window {
		w = &ipWindow{windowStart: now}
		a.byIP[ip] = w
	}
	w.count++

	if w.count > a.threshold && !w.emitted {
		w.emitted = true
		return &Event{
			Type:        EventHTTPErrorSpike,
			Ts:          now,
			WindowStart: w.windowStart,
			SourceIP:    ip,
			StatusClass: statusClass,
			Count:       w.count,
		}
	}
	return nil
}

// pathKey identifies one (source IP, request path) pair being tracked by
// PathSpikeAggregator. A struct key avoids any ambiguity/collision risk from
// concatenating ip+path as a single string.
type pathKey struct {
	ip   string
	path string
}

// PathSpikeAggregator maintains a rolling 1-minute per-(IP, path) request
// counter, counting every request regardless of response status — complements
// SpikeAggregator, which only counts 4xx/5xx. Emits exactly ONE
// http_path_brute_force event per (ip, path, window) when the count first
// exceeds threshold, same one-event-per-window discipline as SpikeAggregator
// (NFR-5).
type PathSpikeAggregator struct {
	mu        sync.Mutex
	threshold int
	window    time.Duration
	byKey     map[pathKey]*ipWindow
}

// NewPathSpikeAggregator creates an aggregator with the given per-(IP, path)
// threshold. threshold <= 0 falls back to DefaultPathBruteForceThreshold.
func NewPathSpikeAggregator(threshold int) *PathSpikeAggregator {
	if threshold <= 0 {
		threshold = DefaultPathBruteForceThreshold
	}
	return &PathSpikeAggregator{
		threshold: threshold,
		window:    time.Minute,
		byKey:     map[pathKey]*ipWindow{},
	}
}

// Observe records one request to path from ip at time now and returns a
// non-nil Event exactly once per rolling window when the threshold is first
// crossed, regardless of the request's response status.
func (a *PathSpikeAggregator) Observe(ip, path string, now time.Time) *Event {
	a.mu.Lock()
	defer a.mu.Unlock()

	key := pathKey{ip: ip, path: path}
	w, ok := a.byKey[key]
	if !ok || now.Sub(w.windowStart) >= a.window {
		w = &ipWindow{windowStart: now}
		a.byKey[key] = w
	}
	w.count++

	if w.count > a.threshold && !w.emitted {
		w.emitted = true
		return &Event{
			Type:        EventHTTPPathBruteForce,
			Ts:          now,
			WindowStart: w.windowStart,
			SourceIP:    ip,
			Path:        path,
			Count:       w.count,
		}
	}
	return nil
}
