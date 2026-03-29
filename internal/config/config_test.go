package config

import (
	"os"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.ModDir != "./modules" {
		t.Errorf("expected default ModDir './modules', got '%s'", cfg.ModDir)
	}
	if cfg.Verbose != false {
		t.Errorf("expected default Verbose false")
	}
}

func TestConfigEnvironmentOverride(t *testing.T) {
	os.Setenv("ASTRA_MOD_DIR", "/tmp/modules")
	defer os.Unsetenv("ASTRA_MOD_DIR")

	cfg, err := LoadConfig("")
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.ModDir != "/tmp/modules" {
		t.Errorf("expected overridden ModDir '/tmp/modules', got '%s'", cfg.ModDir)
	}
}

func TestConfigFileOverride(t *testing.T) {
	content := `
mod_dir: "/etc/astra/modules"
verbose: true
`
	tmpFile := "test_config.yaml"
	os.WriteFile(tmpFile, []byte(content), 0644)
	defer os.Remove(tmpFile)

	cfg, err := LoadConfig(tmpFile)
	if err != nil {
		t.Fatalf("failed to load config: %v", err)
	}

	if cfg.ModDir != "/etc/astra/modules" {
		t.Errorf("expected file overridden ModDir, got '%s'", cfg.ModDir)
	}
	if cfg.Verbose != true {
		t.Errorf("expected file overridden Verbose true")
	}
}
