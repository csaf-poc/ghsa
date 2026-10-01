// Package config loads the optional converter configuration file.
package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"slices"
)

// Config is the content of the file passed via --config.
type Config struct {
	Publisher *Publisher `json:"publisher,omitempty"`
}

// Publisher overrides the CSAF document publisher. Empty fields keep the value
// derived from the advisory.
type Publisher struct {
	Category         string `json:"category,omitempty"`
	Name             string `json:"name,omitempty"`
	Namespace        string `json:"namespace,omitempty"`
	ContactDetails   string `json:"contact_details,omitempty"`
	IssuingAuthority string `json:"issuing_authority,omitempty"`
}

// publisherCategories are the values allowed for document.publisher.category in CSAF 2.0.
var publisherCategories = []string{"coordinator", "discoverer", "other", "translator", "user", "vendor"}

// Load reads and validates a JSON config file.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("could not read config: %w", err)
	}

	var cfg Config
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&cfg); err != nil {
		return nil, fmt.Errorf("could not parse config %s: %w", path, err)
	}

	if p := cfg.Publisher; p != nil && p.Category != "" && !slices.Contains(publisherCategories, p.Category) {
		return nil, fmt.Errorf("invalid publisher category %q in %s (allowed: %v)", p.Category, path, publisherCategories)
	}
	return &cfg, nil
}
