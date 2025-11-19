package internal

import (
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

const documentCategory = "GitHub Security Advisory"

// TODO(lebogg): Implement
func ToCSAF(adv *repository.Advisory) (doc *csaf.Document, err error) {
	doc = &csaf.Document{
		Acknowledgements:  getAcknowledgements(adv),
		AggregateSeverity: nil, // n/a in GHSA
		Category:          getCategory(),
		CSAFVersion:       getVersion(),
		Distribution:      getDistribution(),
		Lang:              nil,
		Notes:             nil,
		Publisher:         nil,
		References:        nil,
		SourceLang:        nil,
		Title:             getTitle(adv),
		Tracking:          nil,
	}
	return nil, nil
}

func getAcknowledgements(adv *repository.Advisory) *gocsaf.Acknowledgements {
	var (
		ack gocsaf.Acknowledgements
	)

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

func getTitle(adv *repository.Advisory) *string {
	if adv.Summary == "" {
		return nil
	}
	return &adv.Summary
}
