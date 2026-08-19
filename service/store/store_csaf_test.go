package store

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/csaf-poc/ghsa/models/csaf"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"github.com/stretchr/testify/assert"
)

func TestSaveAll(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "store_test")
	assert.NoError(t, err)
	defer os.RemoveAll(tmpDir)

	trackingID := gocsaf.TrackingID("GHSA-xxxx-yyyy-zzzz")
	title := "Test Advisory"
	adv := &csaf.Advisory{
		Document: &gocsaf.Document{
			Title: &title,
			Tracking: &gocsaf.Tracking{
				ID: &trackingID,
			},
		},
	}

	err = SaveAll([]*csaf.Advisory{adv}, tmpDir)
	assert.NoError(t, err)

	expectedFilename := "ghsa-xxxx-yyyy-zzzz.json"
	expectedPath := filepath.Join(tmpDir, expectedFilename)
	_, err = os.Stat(expectedPath)
	assert.NoError(t, err, "File should exist with lowercase tracking ID as name")
}
