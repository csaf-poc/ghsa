package converter

import (
	"fmt"
	"log/slog"

	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa"
)

const documentCategory = "GitHub Security Advisory"

// ToCSAF converts a GHSA Advisory into a CSAF Advisory aggregating document, product tree and vulnerabilities.
func ToCSAF(adv ghsa.GHSAAdvisory) (csafadvisory *csaf.Advisory, err error) {
	var (
		d  *csaf.Document
		pt *csaf.ProductTree
		v  csaf.Vulnerabilities
	)
	slog.Info("Converting advisory to CSAF document",
		slog.String("GHSA ID", adv.GetGhsaID()))

	d, err = getDocument(adv)
	if err != nil {
		err = fmt.Errorf("could not extract csaf document: %v", err)
	}
	pt, err = getProductTree(adv)
	if err != nil {
		err = fmt.Errorf("could not extract csaf product tree: %v", err)
	}
	v, err = getVulnerabilities(adv, pt)
	if err != nil {
		err = fmt.Errorf("could not extract csaf vulnerabilities: %v", err)
	}

	csafadvisory = &csaf.Advisory{
		Document:        d,
		ProductTree:     pt,
		Vulnerabilities: v,
	}
	return
}
