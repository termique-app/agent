package security

import (
	"os"
	"path/filepath"
	"testing"
)

func TestTailNewLines_FirstEverPollStartsAtEOFNotZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	state := &State{Sources: map[string]SourceState{}}
	src := Source{Name: "auth", Path: path}

	// A source with no prior recorded state (never seen before — true on a
	// fresh install, and would recur on every restart before state
	// persistence was fixed) must NOT re-process the file's entire existing
	// content as "new" — it starts tailing from the current end only.
	lines, err := TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 0 {
		t.Fatalf("expected no lines on a never-seen-before source, got %+v", lines)
	}

	// Append more content, without re-opening a new file — simulates a
	// normal (non-rotated) log growing.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("failed to open for append: %v", err)
	}
	if _, err := f.WriteString("line3\n"); err != nil {
		t.Fatalf("failed to append: %v", err)
	}
	f.Close()

	lines, err = TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "line3" {
		t.Fatalf("expected only the newly appended line, got %+v", lines)
	}
}

func TestTailNewLines_ResumesFromLastOffset(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line1\nline2\n"), 0o600); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	// Seed a KNOWN state at offset 0, simulating a source the agent has
	// already been tracking from the start — distinct from the never-seen-
	// before case covered by TestTailNewLines_FirstEverPollStartsAtEOFNotZero.
	state := &State{Sources: map[string]SourceState{path: {Offset: 0}}}
	src := Source{Name: "auth", Path: path}

	lines, err := TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 2 || lines[0] != "line1" || lines[1] != "line2" {
		t.Fatalf("unexpected lines on first read: %+v", lines)
	}

	// Append more content, without re-opening a new file — simulates a
	// normal (non-rotated) log growing.
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("failed to open for append: %v", err)
	}
	if _, err := f.WriteString("line3\n"); err != nil {
		t.Fatalf("failed to append: %v", err)
	}
	f.Close()

	lines, err = TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "line3" {
		t.Fatalf("expected only the newly appended line, got %+v", lines)
	}
}

func TestTailNewLines_PartialTrailingLineNotConsumed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line1\npartial-no-newline-yet"), 0o600); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	// Seed a KNOWN state at offset 0 — see TestTailNewLines_ResumesFromLastOffset.
	state := &State{Sources: map[string]SourceState{path: {Offset: 0}}}
	src := Source{Name: "auth", Path: path}

	lines, err := TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "line1" {
		t.Fatalf("expected only the complete line, got %+v", lines)
	}

	// Complete the partial line and confirm it's picked up whole next time,
	// with no truncation or duplication of "line1".
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatalf("failed to open for append: %v", err)
	}
	if _, err := f.WriteString("-now-complete\n"); err != nil {
		t.Fatalf("failed to append: %v", err)
	}
	f.Close()

	lines, err = TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "partial-no-newline-yet-now-complete" {
		t.Fatalf("expected the completed line whole, got %+v", lines)
	}
}

func TestTailNewLines_TruncationResumesFromZero(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "auth.log")
	if err := os.WriteFile(path, []byte("line1\nline2\nline3\n"), 0o600); err != nil {
		t.Fatalf("failed to write test log: %v", err)
	}

	state := &State{Sources: map[string]SourceState{}}
	src := Source{Name: "auth", Path: path}

	if _, err := TailNewLines(src, state); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Simulate an in-place truncation (some tools do this instead of
	// rename+recreate) with brand-new, shorter content.
	if err := os.WriteFile(path, []byte("new-line-a\n"), 0o600); err != nil {
		t.Fatalf("failed to truncate/rewrite test log: %v", err)
	}

	lines, err := TailNewLines(src, state)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(lines) != 1 || lines[0] != "new-line-a" {
		t.Fatalf("expected exactly the new post-truncation line with no stall, got %+v", lines)
	}
}

func TestTailNewLines_MissingSourceIsNotAnError(t *testing.T) {
	state := &State{Sources: map[string]SourceState{}}
	src := Source{Name: "fail2ban", Path: "/nonexistent/path/does-not-exist.log"}

	lines, err := TailNewLines(src, state)
	if err != nil {
		t.Fatalf("expected no error for a missing source, got %v", err)
	}
	if lines != nil {
		t.Fatalf("expected no lines for a missing source, got %+v", lines)
	}
}

func TestDetectSources_SkipsAbsentPaths(t *testing.T) {
	// On a bare test environment none of the fixed v1 paths are expected to
	// exist (and if they happen to, that's still not an error) — this test
	// mainly verifies DetectSources never panics/errors and only returns
	// sources whose files actually exist, plus an explicitly-provided
	// reverse-proxy path when it exists.
	dir := t.TempDir()
	rp := filepath.Join(dir, "access.log")
	if err := os.WriteFile(rp, []byte(""), 0o600); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}

	sources := DetectSources(rp)
	found := false
	for _, s := range sources {
		if s.Name == "reverse_proxy" {
			found = true
			if s.Path != rp {
				t.Fatalf("expected reverse_proxy path %s, got %s", rp, s.Path)
			}
		}
	}
	if !found {
		t.Fatal("expected an existing reverse-proxy log path to be detected")
	}

	sources = DetectSources(filepath.Join(dir, "does-not-exist.log"))
	for _, s := range sources {
		if s.Name == "reverse_proxy" {
			t.Fatal("expected a nonexistent reverse-proxy path to be skipped")
		}
	}
}
