package store

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/csaf"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

// Save writes the CSAF advisory to the given file name using gocsaf's encoder
func Save(adv *csaf.Advisory, fname string) (err error) {
	slog.Info("Saving advisory",
		slog.Any("CSAF advisory", utils.Deref(adv.Document.Title)),
		slog.String("file name", fname))
	err = gocsaf.SaveAdvisory(adv, fname)
	if err != nil {
		// We don't need to wrap err because it is used as is in main
		return err
	}
	slog.Info("Saved advisory",
		slog.Any("CSAF Document Title", utils.Deref(adv.Document.Title)),
		slog.Any("Tracking ID", utils.Deref(adv.Document.Tracking.ID)),
		slog.String("file name", fname))
	return
}

// SaveAll writes a collection of CSAF advisories into the specified directory.
// Each advisory is saved as a JSON file named after its Tracking ID.
func SaveAll(advisories []*csaf.Advisory, dir string) error {
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("could not create output directory: %v", err)
	}

	for _, adv := range advisories {
		if adv.Document == nil || adv.Document.Tracking.ID == nil {
			slog.Warn("Skipping advisory with missing tracking ID")
			continue
		}

		id := string(utils.Deref(adv.Document.Tracking.ID))
		// Basic normalization to ensure filename safety if not using a full helper
		filename := strings.ToLower(id) + ".json"
		path := filepath.Join(dir, filename)

		if err := Save(adv, path); err != nil {
			return fmt.Errorf("failed to save advisory %s: %v", id, err)
		}
	}
	return nil
}
