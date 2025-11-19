package internal

import (
	"errors"
	"log/slog"

	"github.com/csaf-poc/ghsa/models/csaf"
)

// TODO(lebogg): Implement
func StoreCSAF(csaf *csaf.Document) error {
	slog.Info("Not implemented yet")
	return errors.New("not implemented yet")
}
