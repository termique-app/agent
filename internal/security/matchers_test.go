package security

import (
	"testing"
	"time"
)

func TestMatchLine_SSHAuthFail(t *testing.T) {
	now := time.Now()
	ev := MatchLine("auth", "Jul 22 10:15:32 host sshd[1234]: Failed password for invalid user admin from 203.0.113.5 port 51515 ssh2", now)
	if ev == nil {
		t.Fatal("expected a match, got nil")
	}
	if ev.Type != EventSSHAuthFail {
		t.Fatalf("expected ssh_auth_fail, got %s", ev.Type)
	}
	if ev.Username != "admin" || ev.SourceIP != "203.0.113.5" {
		t.Fatalf("unexpected fields: username=%s source_ip=%s", ev.Username, ev.SourceIP)
	}
}

func TestMatchLine_SSHAuthSuccess(t *testing.T) {
	now := time.Now()
	ev := MatchLine("auth", "Jul 22 10:16:01 host sshd[1240]: Accepted publickey for deploy from 198.51.100.9 port 51520 ssh2", now)
	if ev == nil {
		t.Fatal("expected a match, got nil")
	}
	if ev.Type != EventSSHAuthSuccess {
		t.Fatalf("expected ssh_auth_success, got %s", ev.Type)
	}
	if ev.Username != "deploy" || ev.SourceIP != "198.51.100.9" {
		t.Fatalf("unexpected fields: username=%s source_ip=%s", ev.Username, ev.SourceIP)
	}
}

func TestMatchLine_Fail2banBanAndUnban(t *testing.T) {
	now := time.Now()

	ban := MatchLine("fail2ban", "2026-07-22 10:15:32,123 fail2ban.actions [123]: NOTICE [sshd] Ban 203.0.113.5", now)
	if ban == nil || ban.Type != EventFail2banBan {
		t.Fatalf("expected fail2ban_ban, got %+v", ban)
	}
	if ban.Jail != "sshd" || ban.IP != "203.0.113.5" {
		t.Fatalf("unexpected fields: jail=%s ip=%s", ban.Jail, ban.IP)
	}

	unban := MatchLine("fail2ban", "2026-07-22 11:15:32,123 fail2ban.actions [123]: NOTICE [sshd] Unban 203.0.113.5", now)
	if unban == nil || unban.Type != EventFail2banUnban {
		t.Fatalf("expected fail2ban_unban, got %+v", unban)
	}
}

func TestMatchLine_NoMatch(t *testing.T) {
	now := time.Now()
	if ev := MatchLine("auth", "Jul 22 10:15:32 host sshd[1234]: Server listening on 0.0.0.0 port 22.", now); ev != nil {
		t.Fatalf("expected no match, got %+v", ev)
	}
	if ev := MatchLine("unknown-source", "anything", now); ev != nil {
		t.Fatalf("expected no match for unknown source, got %+v", ev)
	}
}

func TestMatchAccessLine(t *testing.T) {
	line := `203.0.113.7 - - [22/Jul/2026:10:15:32 +0000] "GET /nonexistent HTTP/1.1" 404 512 "-" "-"`
	ip, statusClass, ok := MatchAccessLine(line)
	if !ok {
		t.Fatal("expected a match")
	}
	if ip != "203.0.113.7" || statusClass != "4xx" {
		t.Fatalf("unexpected fields: ip=%s statusClass=%s", ip, statusClass)
	}

	okLine := `203.0.113.7 - - [22/Jul/2026:10:15:32 +0000] "GET / HTTP/1.1" 200 512 "-" "-"`
	if _, _, ok := MatchAccessLine(okLine); ok {
		t.Fatal("expected 2xx line to not match (not a 4xx/5xx)")
	}

	if _, _, ok := MatchAccessLine("not a log line at all"); ok {
		t.Fatal("expected garbage line to not match")
	}
}

func TestSpikeAggregator_EmitsExactlyOncePerWindow(t *testing.T) {
	agg := NewSpikeAggregator(30)
	base := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	var events []*Event
	for i := 0; i < 31; i++ {
		// All within the same 1-minute window.
		ts := base.Add(time.Duration(i) * time.Second)
		if ev := agg.Observe("203.0.113.5", "4xx", ts); ev != nil {
			events = append(events, ev)
		}
	}

	if len(events) != 1 {
		t.Fatalf("expected exactly 1 spike event for 31 requests in one window, got %d", len(events))
	}
	if events[0].Count != 31 {
		t.Fatalf("expected count=31, got %d", events[0].Count)
	}

	// More requests in the SAME window must not emit again.
	if ev := agg.Observe("203.0.113.5", "4xx", base.Add(45*time.Second)); ev != nil {
		t.Fatalf("expected no further event within the same window, got %+v", ev)
	}
}

func TestSpikeAggregator_BelowThresholdNeverEmits(t *testing.T) {
	agg := NewSpikeAggregator(30)
	base := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	for i := 0; i < 30; i++ {
		if ev := agg.Observe("203.0.113.5", "5xx", base.Add(time.Duration(i)*time.Second)); ev != nil {
			t.Fatalf("expected no event below/at threshold, got one at i=%d: %+v", i, ev)
		}
	}
}

func TestSpikeAggregator_NewWindowResetsAndCanEmitAgain(t *testing.T) {
	agg := NewSpikeAggregator(2)
	base := time.Date(2026, 7, 22, 10, 0, 0, 0, time.UTC)

	// Cross the threshold in window 1.
	agg.Observe("203.0.113.5", "4xx", base)
	agg.Observe("203.0.113.5", "4xx", base.Add(1*time.Second))
	ev := agg.Observe("203.0.113.5", "4xx", base.Add(2*time.Second))
	if ev == nil {
		t.Fatal("expected a spike event crossing the threshold in window 1")
	}

	// A new window (>= 1 minute later) should reset the counter and be able
	// to emit again once the threshold is crossed there too.
	next := base.Add(90 * time.Second)
	agg.Observe("203.0.113.5", "4xx", next)
	agg.Observe("203.0.113.5", "4xx", next.Add(1*time.Second))
	ev2 := agg.Observe("203.0.113.5", "4xx", next.Add(2*time.Second))
	if ev2 == nil {
		t.Fatal("expected a new spike event in the next window")
	}
	if ev2.WindowStart != next {
		t.Fatalf("expected new window's WindowStart to reset, got %v", ev2.WindowStart)
	}
}
