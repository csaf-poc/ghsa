package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestLoad(t *testing.T) {
	cfg, err := Load(writeConfig(t, `{"publisher": {"category": "vendor", "name": "ACME", "namespace": "https://acme.example"}}`))
	if err != nil {
		t.Fatalf("Load returned error: %v", err)
	}
	if cfg.Publisher == nil || cfg.Publisher.Category != "vendor" || cfg.Publisher.Name != "ACME" || cfg.Publisher.Namespace != "https://acme.example" {
		t.Errorf("unexpected publisher: %#v", cfg.Publisher)
	}
}

func TestLoad_Invalid(t *testing.T) {
	for name, content := range map[string]string{
		"bad category":  `{"publisher": {"category": "maintainer"}}`,
		"unknown field": `{"publisher": {"nmae": "typo"}}`,
		"not json":      `publisher: x`,
	} {
		if _, err := Load(writeConfig(t, content)); err == nil {
			t.Errorf("%s: expected error", name)
		}
	}
}
