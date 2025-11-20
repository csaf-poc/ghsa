package internal

import (
	"fmt"
	"sync/atomic"

	"github.com/csaf-poc/ghsa/internal/utils"
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
// TODO(lebogg): Check if all required fields are set!
// TODO(lebogg): For names we currently use login names because these are mandatory while names arent. BUT logins can change so maybe we should combine it with id (number)?
// TODO(lebogg): Currently, we only provide the document but we do not provide the vulnerabilities -> return advisory
func getDocument(adv *repository.Advisory) (doc *csaf.Document, err error) {
	doc = &csaf.Document{
		Acknowledgements:  getAcknowledgements(adv),
		AggregateSeverity: nil,           // n/a in GHSA
		Category:          getCategory(), // required
		CSAFVersion:       getVersion(),  // required
		Distribution:      getDistribution(),
		Lang:              getLang(adv), // no language info in GHSA, default to "en"
		Notes:             getNotes(adv),
		Publisher:         getPublisher(&adv.Publisher), // required
		References:        nil,                          // TODO(lebogg): Implement (optional)
		SourceLang:        nil,                          // TODO(lebogg): Implement (optional)
		Title:             getTitle(adv),                // required
		Tracking:          getTracking(adv),             // required
	}
	return
}

// TODO(lebogg): Implement
func getProductTree(_ *repository.Advisory) (*csaf.ProductTree, error) {
	panic("TODO")
}

// TODO(lebogg): Implement
func getVulnerabilities(_ *repository.Advisory) (csaf.Vulnerabilities, error) {
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

// TODO(lebogg): In the case of GHSA, is GH the publisher or the single persons/entities themselves?
func getPublisher(ghsapublisher *repository.User) (p *gocsaf.DocumentPublisher) {
	var (
		category         = gocsaf.CSAFCategoryDiscoverer // TODO: Could also be others (if we are not sure)?
		name             = ghsapublisher.Login           // We use Login because it is required while name isn't
		issuingAuthority = "GitHub"                      // Assumption: GitHub is the issuing authority
	)

	p = &gocsaf.DocumentPublisher{
		Category:         &category, // required
		ContactDetails:   provideContactInformation(ghsapublisher),
		IssuingAuthority: &issuingAuthority,
		Name:             &name,                  // required
		Namespace:        &ghsapublisher.HTMLURL, // required. Assumption: HTMLURL fulfills the namespace requirement
	}
	return
}

func getTitle(adv *repository.Advisory) *string {
	if adv.Summary == "" {
		return nil
	}
	return &adv.Summary
}

// TODO(lebogg): Implement
func getTracking(adv *repository.Advisory) (tracking *gocsaf.Tracking) {
	var (
		id = gocsaf.TrackingID(adv.GhsaID)
	)

	revisionHistory := getRevisionHistory(adv)

	tracking = &gocsaf.Tracking{
		Aliases: getAliases(adv.Identifiers),
		// TODO(lebogg):  Check format (is ISO 8601)
		CurrentReleaseDate: getCurrentReleaseDate(adv), // required
		Generator:          nil,
		ID:                 &id, // required
		// TODO(lebogg):  Check format (is ISO 8601)
		InitialReleaseDate: &adv.PublishedAt,                                             // required. Assumption: UpdatedAt doesn't represent release dates
		RevisionHistory:    revisionHistory,                                              // required
		Status:             utils.Ref(gocsaf.CSAFTrackingStatusFinal),                    // required. Assumption: GHSA is final
		Version:            utils.Ref(gocsaf.RevisionNumber(rune(len(revisionHistory)))), // required
	}
	return

}

func getCurrentReleaseDate(adv *repository.Advisory) (current *string) {
	if adv.UpdatedAt != "" && adv.UpdatedAt > adv.PublishedAt {
		current = &adv.UpdatedAt
		return
	}
	current = &adv.PublishedAt
	return
}

func getAliases(identifiers []repository.Identifier) (aliases []*string) {
	aliases = make([]*string, len(identifiers))
	for i, id := range identifiers {
		aliases[i] = &id.Value
	}
	return
}

// getRevisionHistory processes the advisory and returns its chronological revision history as a slice of revisions.
// Note: GHSA does not provide a revision history, so we create one based on the publication date and the update date.
func getRevisionHistory(adv *repository.Advisory) (revisions gocsaf.Revisions) {
	var (
		n = atomic.Int32{}
	)
	// Published
	if adv.PublishedAt != "" {
		revNumber := gocsaf.RevisionNumber(n.Add(1))
		revisions = append(revisions, &gocsaf.Revision{
			Date:    &adv.PublishedAt,
			Number:  &revNumber,
			Summary: utils.Ref("Advisory published"),
		})
	}
	// Updated after publication (ISO 8601 strings are lexicographically sortable, so string comparison should work.)
	if adv.UpdatedAt != "" && adv.UpdatedAt != adv.PublishedAt && adv.UpdatedAt > adv.PublishedAt {
		revNumber := gocsaf.RevisionNumber(n.Add(1))
		revisions = append(revisions, &gocsaf.Revision{
			Date:    &adv.UpdatedAt,
			Number:  &revNumber,
			Summary: utils.Ref("Advisory updated"),
		})
	}
	return
}

func provideContactInformation(u *repository.User) (contactInformation *string) {
	var (
		info string
	)
	// First set HTML URL as URL because this is the place where profile information is shared publicly
	info = "URL: " + u.HTMLURL
	// Add email information if it is provided
	if u.Email != "" {
		info = info + "; email: " + u.Email
	}

	contactInformation = &info
	return
}
