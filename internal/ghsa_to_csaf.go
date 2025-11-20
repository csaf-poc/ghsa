package internal

import (
	"fmt"

	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
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

// TODO(lebogg): Fill out document
// TODO(lebogg): Currently, we only provide the document but we do not provide the vulnerabilities -> return advisory
func getDocument(adv *repository.Advisory) (doc *csaf.Document, err error) {
	doc = &csaf.Document{
		Acknowledgements:  getAcknowledgements(adv),
		AggregateSeverity: nil, // n/a in GHSA
		Category:          getCategory(),
		CSAFVersion:       getVersion(),
		Distribution:      getDistribution(),
		Lang:              getLang(adv), // no language info in GHSA, default to "en"
		Notes:             getNotes(adv),
		Publisher:         nil,
		References:        nil,
		SourceLang:        nil,
		Title:             getTitle(adv),
		Tracking:          nil,
	}
	return
}

// TODO(lebogg): Implement
func getProductTree(a *repository.Advisory) (*csaf.ProductTree, error) {
	panic("TODO")
}

// TODO(lebogg): Implement
func getVulnerabilities(a *repository.Advisory) (csaf.Vulnerabilities, error) {
	panic("TODO")
}

// getAcknowledgements converts GHSA detailed credits into CSAF acknowledgments.
// Returns nil if no credits exist.
// For each entry in adv.CreditsDetailed it creates one Acknowledgement:
// \- Login used as Names (because full name may be absent)
// \- OrganizationsURL as Organization
// \- credit.Type mapped via creditTypeToSummary as Summary (nil if empty)
// \- HTMLURL placed in URLs
// No grouping is performed.
func getAcknowledgements(adv *repository.Advisory) *gocsaf.Acknowledgements {
	var (
		ack gocsaf.Acknowledgements
	)
	// Return nil if no credits are provided
	if len(adv.CreditsDetailed) == 0 {
		return nil
	}

	// Add credited users
	for _, credit := range adv.CreditsDetailed {
		ack = append(ack, &gocsaf.Acknowledgement{
			// We use the login as a name because it is required and the full name may be empty
			Names:        []*string{&credit.User.Login},
			Organization: &credit.User.OrganizationsURL,
			// Use credit type as summary if available
			Summary: creditTypeToSummary(credit.Type),
			URLs:    []*string{&credit.User.HTMLURL},
		})
	}
	return &ack
}

// creditTypeToSummary returns a *string with a human-readable role description.
// Nil is returned if no credit type is provided.
func creditTypeToSummary(creditType string) (summary *string) {
	var (
		phrase string
	)

	// If no credit type is provided, return nil
	if creditType == "" {
		summary = nil
		return
	}

	// Map credit type to human-readable phrase
	switch creditType {
	case "REPORTER", "FINDER":
		phrase = "Reported the vulnerability"
	case "ANALYZER":
		phrase = "Analyzed impact"
	case "FIXER":
		phrase = "Provided the fix"
	case "REVIEWER":
		phrase = "Reviewed the fix"
	case "COORDINATOR":
		phrase = "Coordinated disclosure"
	default:
		// Fallback: use raw type
		phrase = creditType
	}
	// Return the phrase as a *string
	summary = &phrase
	return
}

func getCategory() *gocsaf.DocumentCategory {
	cat := gocsaf.DocumentCategory(documentCategory)
	return &cat
}

func getVersion() *gocsaf.Version {
	v := gocsaf.CSAFVersion20 // Currently only CSAF 2.0 is supported
	return &v
}

func getDistribution() *gocsaf.DocumentDistribution {
	label := gocsaf.TLPLabel(gocsaf.TLPLabelWhite) // Default TLP label is White
	dist := gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: &label,
		},
	}
	return &dist
}

// getLang extracts the default language as "en" for the given Advisory because GHSA does not provide language
// information and on GitHub the common language is English.
func getLang(_ *repository.Advisory) (lang *gocsaf.Lang) {
	var (
		l gocsaf.Lang
	)
	l = "en"
	lang = &l
	return
}

func getNotes(adv *repository.Advisory) (notes gocsaf.Notes) {
	var (
		titleSummary        = "Summary"
		categorySummary     = gocsaf.CSAFNoteCategorySummary
		titleDescription    = "Description"
		categoryDescription = gocsaf.CSAFNoteCategoryDescription
	)
	if adv == nil {
		return
	}

	if adv.Summary != "" {
		summaryNote := &gocsaf.Note{
			NoteCategory: &categorySummary,
			Text:         &adv.Summary,
			Title:        &titleSummary,
		}
		notes = append(notes, summaryNote)

	}
	if adv.Description != "" {
		descriptionNote := &gocsaf.Note{
			NoteCategory: &categoryDescription,
			Text:         &adv.Description,
			Title:        &titleDescription,
		}
		notes = append(notes, descriptionNote)
	}
	return
}

func getTitle(adv *repository.Advisory) *string {
	if adv.Summary == "" {
		return nil
	}
	return &adv.Summary
}
