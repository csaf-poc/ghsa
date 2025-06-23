package internal

import (
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

// TODO(lebogg): Implement
func ToCSAF(ghsa *repository.Advisory) (csaf *csaf.Document, err error) {
	return nil, nil
}
