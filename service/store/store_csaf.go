package store

import (
	"log/slog"

	"github.com/csaf-poc/ghsa/models/csaf"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

func Save(adv *csaf.Advisory, fname string) (err error) {
	slog.Info("Saving advisory",
		slog.Any("CSAF advisory", adv), // TODO(lebogg): Check that this does not explode since too much info
		slog.String("file name", fname))
	err = gocsaf.SaveAdvisory(adv, fname)
	if err != nil {
		// We don't need to wrap err because it is used as is in main
		return err
	}
	return
}
