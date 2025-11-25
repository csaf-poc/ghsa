package converter

import (
	"fmt"

	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

const documentCategory = "GitHub Security Advisory"

func ToCSAF(a *repository.Advisory) (csafadvisory *csaf.Advisory, err error) {
	var (
		d  *csaf.Document
		pt *csaf.ProductTree
		v  csaf.Vulnerabilities
	)

	d, err = getDocument(a)
	if err != nil {
		err = fmt.Errorf("could not extract csaf document: %v", err)
	}
	pt, err = getProductTree(a)
	if err != nil {
		err = fmt.Errorf("could not extract csaf product tree: %v", err)
	}
	v, err = getVulnerabilities(a)
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
