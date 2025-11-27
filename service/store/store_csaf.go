package store

import (
	"log/slog"

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
