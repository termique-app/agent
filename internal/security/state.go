package security

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// SourceState tracks tailing progress for one watched log source, keyed by
// absolute file path in State.Sources. Offset is the last byte position
// read; Inode is used to detect log rotation (a renamed-and-recreated file
// gets a new inode even though the path is unchanged).
type SourceState struct {
	Offset int64  `json:"offset"`
	Inode  uint64 `json:"inode"`
}

// State is the on-disk persisted tailing state for all watched sources.
// Survives agent restarts (FR-1.3) — without this, every restart would
// either re-emit already-seen lines (if resuming from 0) or silently miss
// lines written while the agent was down (if resuming from current EOF).
type State struct {
	Sources map[string]SourceState `json:"sources"`
}

// LoadState reads the state file at path. A missing file is not an error —
// it just means this is a fresh install with no prior tailing progress, so
// every source starts tailing from its current position on first poll.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{Sources: map[string]SourceState{}}, nil
		}
		return nil, err
	}
	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		// A corrupt state file is not fatal — start fresh rather than
		// refusing to run. Losing tailing position is far less bad than
		// crash-looping the whole agent over a malformed JSON file.
		return &State{Sources: map[string]SourceState{}}, nil
	}
	if st.Sources == nil {
		st.Sources = map[string]SourceState{}
	}
	return &st, nil
}

// Save persists the state atomically: write to a temp file in the same
// directory, then rename over the real path. This avoids a truncated/corrupt
// state file if the process is killed mid-write.
func (s *State) Save(path string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.Marshal(s)
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
