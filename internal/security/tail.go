package security

import (
	"bufio"
	"io"
	"os"
	"strings"
	"syscall"
)

// Source is one watched log source.
type Source struct {
	// Name is the logical source kind ("auth", "fail2ban", "reverse_proxy")
	// used by the caller to pick the right matcher (MatchLine/MatchAccessLine).
	Name string
	Path string
}

// DetectSources returns the fixed v1 log sources that actually exist on this
// host (FR-1.2). Auto-detected sources that don't exist are silently
// skipped, never an error — most hosts won't have all three present.
func DetectSources(reverseProxyLogPath string) []Source {
	var sources []Source

	// auth.log (Debian/Ubuntu) and secure (RHEL-family) are alternatives for
	// the same logical source — at most one will exist on a given host, but
	// check both since we can't know the distro in advance.
	for _, path := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if fileExists(path) {
			sources = append(sources, Source{Name: "auth", Path: path})
		}
	}

	if fileExists("/var/log/fail2ban.log") {
		sources = append(sources, Source{Name: "fail2ban", Path: "/var/log/fail2ban.log"})
	}

	if reverseProxyLogPath != "" && fileExists(reverseProxyLogPath) {
		sources = append(sources, Source{Name: "reverse_proxy", Path: reverseProxyLogPath})
	}

	return sources
}

func fileExists(path string) bool {
	if path == "" {
		return false
	}
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func inodeOf(info os.FileInfo) uint64 {
	if stat, ok := info.Sys().(*syscall.Stat_t); ok {
		return stat.Ino
	}
	return 0
}

// TailNewLines reads any complete lines appended to src since state's
// last-recorded offset for src.Path, updating state in place. It detects
// rotation via inode change (renamed + recreated at the same path) or
// truncation (file shrank below the last offset) and resumes from byte 0 of
// the new/truncated file — never re-emitting already-seen lines, never
// permanently stalling on a rotated file (FR-1.3).
//
// A trailing partial line (no terminating '\n' yet, e.g. a write in
// progress) is intentionally left unconsumed — the offset is not advanced
// past it, so it is re-read whole once it's complete on a later poll.
func TailNewLines(src Source, state *State) ([]string, error) {
	f, err := os.Open(src.Path)
	if err != nil {
		if os.IsNotExist(err) {
			// Source disappeared between polls (e.g. deleted) — treat like
			// "not present" for this poll, don't error the whole loop.
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	info, err := f.Stat()
	if err != nil {
		return nil, err
	}

	prev, known := state.Sources[src.Path]
	inode := inodeOf(info)

	var offset int64
	if known {
		rotated := prev.Inode != 0 && inode != 0 && prev.Inode != inode
		truncated := info.Size() < prev.Offset
		if !rotated && !truncated {
			offset = prev.Offset
		}
		// rotated or truncated: offset stays 0 — resume from start of the
		// "new" file (a rotated file's low offsets are content we've never
		// seen, since the old inode's bytes are gone from this path).
	}

	if offset > 0 {
		if _, err := f.Seek(offset, io.SeekStart); err != nil {
			return nil, err
		}
	}

	lines, consumed, err := readCompleteLines(f, offset)
	if err != nil {
		return nil, err
	}

	state.Sources[src.Path] = SourceState{Offset: consumed, Inode: inode}
	return lines, nil
}

// readCompleteLines reads from r (already positioned at startOffset) to EOF,
// returning only complete (newline-terminated) lines and the exact byte
// offset immediately after the last complete line consumed.
func readCompleteLines(r io.Reader, startOffset int64) ([]string, int64, error) {
	reader := bufio.NewReaderSize(r, 64*1024)
	pos := startOffset
	var lines []string

	for {
		line, err := reader.ReadString('\n')
		if len(line) > 0 && strings.HasSuffix(line, "\n") {
			pos += int64(len(line))
			lines = append(lines, strings.TrimRight(line, "\r\n"))
		}
		if err != nil {
			if err == io.EOF {
				break
			}
			return lines, pos, err
		}
	}

	return lines, pos, nil
}
