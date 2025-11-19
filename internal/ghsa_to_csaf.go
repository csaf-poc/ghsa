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
		Category:          getCategory(adv),
		CSAFVersion:       getVersion(),
		Distribution:      getDistribution(),
		Lang:              nil,
		Notes:             nil,
		Publisher:         nil,
		References:        nil,
		SourceLang:        nil,
		Title:             nil,
		Tracking:          nil,
	}
	return nil, nil
}

func getAcknowledgements(adv *repository.Advisory) *gocsaf.Acknowledgements {
	var ack gocsaf.Acknowledgements
	// Add credited users
	for _, credit := range adv.CreditsDetailed {
		ack = append(ack, &gocsaf.Acknowledgement{
			// Use ID because name is not required
			Names:        []*string{&credit.User.Login},
			Organization: &credit.User.OrganizationsURL,
			Summary:      nil, // Nothing found in GHSA w.r.t. credits
			URLs:         []*string{&credit.User.HTMLURL},
		})
	}
	return &ack
}

func getCategory(adv *repository.Advisory) *gocsaf.DocumentCategory {
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
