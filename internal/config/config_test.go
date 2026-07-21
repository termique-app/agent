package config

import (
	"os"
	"path/filepath"
	"testing"
)

// writeTestConfig writes a config.toml with the given extra body appended
// after the required token/server_id fields, with 0600 permissions (Load
// refuses to run against anything more permissive).
func writeTestConfig(t *testing.T, extra string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.toml")
	body := "token = \"test-token\"\nserver_id = \"test-server\"\n" + extra
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("failed to write test config: %v", err)
	}
	return path
}

func TestLoad_AutoUpdate_DefaultsTrueWhenAbsent(t *testing.T) {
	path := writeTestConfig(t, "")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AutoUpdate == nil {
		t.Fatal("expected AutoUpdate to be defaulted to a non-nil pointer, got nil")
	}
	if *cfg.AutoUpdate != true {
		t.Fatalf("expected AutoUpdate to default to true when key absent, got %v", *cfg.AutoUpdate)
	}
}

func TestLoad_AutoUpdate_ExplicitFalseHonored(t *testing.T) {
	path := writeTestConfig(t, "auto_update = false\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AutoUpdate == nil {
		t.Fatal("expected AutoUpdate to be non-nil")
	}
	if *cfg.AutoUpdate != false {
		t.Fatalf("expected explicit auto_update = false to be honored, got %v", *cfg.AutoUpdate)
	}
}

func TestLoad_AutoUpdate_ExplicitTrueHonored(t *testing.T) {
	path := writeTestConfig(t, "auto_update = true\n")
	cfg, err := Load(path)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.AutoUpdate == nil {
		t.Fatal("expected AutoUpdate to be non-nil")
	}
	if *cfg.AutoUpdate != true {
		t.Fatalf("expected explicit auto_update = true to be honored, got %v", *cfg.AutoUpdate)
	}
}

// TestLoad_AutoUpdate_ZeroValueGotchaWouldFail documents the exact bug this
// design avoids: a plain (non-pointer) bool field cannot distinguish
// "unset, default true" from "explicitly set to false" — both parse to the
// Go zero value false. Asserting *bool nil-checking behavior here guards
// against a future refactor silently reintroducing that bug.
func TestLoad_AutoUpdate_UnsetAndExplicitFalseAreDistinguishable(t *testing.T) {
	unsetPath := writeTestConfig(t, "")
	explicitFalsePath := writeTestConfig(t, "auto_update = false\n")

	unsetCfg, err := Load(unsetPath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	explicitCfg, err := Load(explicitFalsePath)
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}

	if *unsetCfg.AutoUpdate == *explicitCfg.AutoUpdate {
		t.Fatalf(
			"unset config (%v) and explicit auto_update=false (%v) must resolve differently",
			*unsetCfg.AutoUpdate, *explicitCfg.AutoUpdate,
		)
	}
}
