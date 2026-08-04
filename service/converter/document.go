package converter

import (
	"strconv"
	"sync/atomic"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

// getDocument builds the CSAF Document section from a GHSA advisory
func getDocument(adv *repository.Advisory) (doc *csaf.Document, err error) {
	doc = &csaf.Document{
		Acknowledgements:  getAcknowledgements(adv),
		AggregateSeverity: getSeverity(adv),             // not required. n/a in GHSA
		Category:          getCategory(),                // required
		CSAFVersion:       getVersion(),                 // required
		Distribution:      getDistribution(),            // not required
		Lang:              getLang(adv),                 // not required. No language info in GHSA, default to "en"
		Notes:             getNotes(adv),                // not required
		Publisher:         getPublisher(&adv.Publisher), // required
		References:        nil,                          // not required.
		SourceLang:        nil,                          // not required.
		Title:             getTitle(adv),                // required
		Tracking:          getTracking(adv),             // required
	}
	return
}

// getAcknowledgements maps GHSA credits to CSAF acknowledgments.
// It prefers credits_detailed and falls back to credits when detailed credits are absent.
func getAcknowledgements(adv *repository.Advisory) (ack *gocsaf.Acknowledgements) {
	if len(adv.CreditsDetailed) > 0 {
		ack = getAcknowledgementsFromDetailedCredits(adv.CreditsDetailed)
	} else {
		ack = getAcknowledgementsFromCredits(adv.Credits)
	}
	return
}

// getAcknowledgementsFromDetailedCredits maps GHSA detailed credits to CSAF acknowledgments.
func getAcknowledgementsFromDetailedCredits(detailed []repository.CreditDetailed) *gocsaf.Acknowledgements {
	var ack gocsaf.Acknowledgements
	if len(detailed) == 0 {
		return nil
	}

	for _, credit := range detailed {
		displayName := credit.User.Name
		if displayName == "" {
			displayName = credit.User.Login
		}
		if displayName == "" {
			continue
		}

		ack = append(ack, &gocsaf.Acknowledgement{
			Names:        []*string{utils.Ref(displayName)},
			Organization: utils.Ref(credit.User.OrganizationsURL),
			Summary:      creditTypeToSummary(credit.Type),
			URLs:         []*string{utils.Ref(credit.User.HTMLURL)},
		})
	}

	if len(ack) == 0 {
		return nil
	}
	return &ack
}

// getAcknowledgementsFromCredits maps GHSA lightweight credits to CSAF acknowledgments.
func getAcknowledgementsFromCredits(credits []repository.Credit) *gocsaf.Acknowledgements {
	var ack gocsaf.Acknowledgements
	if len(credits) == 0 {
		return nil
	}

	for _, credit := range credits {
		if credit.Login == "" {
			continue
		}
		ack = append(ack, &gocsaf.Acknowledgement{
			Names:   []*string{utils.Ref(credit.Login)},
			Summary: creditTypeToSummary(credit.Type),
		})
	}

	if len(ack) == 0 {
		return nil
	}
	return &ack
}

// getSeverity creates AggregateSeverity from GHSA severity string
func getSeverity(adv *repository.Advisory) (s *gocsaf.AggregateSeverity) {
	s = &gocsaf.AggregateSeverity{
		Namespace: nil,                     // not required
		Text:      utils.Ref(adv.Severity), // required
	}
	return
}

// creditTypeToSummary turns a GHSA credit type into a human-readable summary
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

// getCategory returns the fixed document category
func getCategory() *gocsaf.DocumentCategory {
	cat := gocsaf.DocumentCategory(documentCategory)
	return &cat
}

// getVersion returns the CSAF specification version used
func getVersion() *gocsaf.Version {
	v := gocsaf.CSAFVersion20 // Currently only CSAF 2.0 is supported
	return &v
}

// getDistribution returns a default TLP White distribution
func getDistribution() *gocsaf.DocumentDistribution {
	label := gocsaf.TLPLabel(gocsaf.TLPLabelWhite) // Default TLP label is White
	dist := gocsaf.DocumentDistribution{
		TLP: &gocsaf.TLP{
			DocumentTLPLabel: &label,
		},
	}
	return &dist
}

// getLang returns default language "en" (GHSA lacks language info)
func getLang(_ *repository.Advisory) (lang *gocsaf.Lang) {
	var (
		l gocsaf.Lang
	)
	l = "en"
	lang = &l
	return
}

// getNotes builds summary and description notes from GHSA fields
func getNotes(adv *repository.Advisory) (notes gocsaf.Notes) {
	notes = []*gocsaf.Note{
		{
			NoteCategory: utils.Ref(gocsaf.CSAFNoteCategorySummary),
			Title:        utils.Ref("Summary"),
			Text:         utils.Ref(adv.Summary),
		},
		{
			NoteCategory: utils.Ref(gocsaf.CSAFNoteCategoryDescription),
			Title:        utils.Ref("Description"),
			Text:         utils.Ref(adv.Description),
		},
	}
	return
}

// getPublisher maps GHSA publisher user to CSAF publisher metadata
func getPublisher(ghsapublisher *repository.User) (p *gocsaf.DocumentPublisher) {
	var (
		category         = gocsaf.CSAFCategoryDiscoverer // Assumption: Discoverer is the correct publisher category
		name             = ghsapublisher.Login           // We use Login because it is required while name isn't
		issuingAuthority = "GitHub"                      // Assumption: GitHub is the issuing authority
	)

	p = &gocsaf.DocumentPublisher{
		Category:         &category,                                // required
		ContactDetails:   provideContactInformation(ghsapublisher), // not required
		IssuingAuthority: &issuingAuthority,                        // not required
		Name:             &name,                                    // required
		Namespace:        &ghsapublisher.HTMLURL,                   // required. Assumption: HTMLURL fulfills the namespace requirement
	}
	return
}

// getTitle returns advisory summary or nil if empty
func getTitle(adv *repository.Advisory) *string {
	if adv.Summary == "" {
		return nil
	}
	return &adv.Summary
}

// getTracking assembles tracking information including revision history
func getTracking(adv *repository.Advisory) (tracking *gocsaf.Tracking) {
	var (
		id = gocsaf.TrackingID(adv.GhsaID)
	)

	revisionHistory := getRevisionHistory(adv)

	tracking = &gocsaf.Tracking{
		Aliases:            getAliases(adv.Identifiers),                                          // not required
		CurrentReleaseDate: getCurrentReleaseDate(adv),                                           // required.
		Generator:          getGenerator(),                                                       // optional; we populate it because this converter IS the CSAF engine
		ID:                 utils.Ref(id),                                                        // required
		InitialReleaseDate: utils.Ref(adv.PublishedAt),                                           // required.
		RevisionHistory:    revisionHistory,                                                      // required
		Status:             utils.Ref(gocsaf.CSAFTrackingStatusFinal),                            // required. Assumption: GHSA is final
		Version:            utils.Ref(gocsaf.RevisionNumber(strconv.Itoa(len(revisionHistory)))), // required
	}
	return

}

// getGenerator returns the CSAF Generator identifying this converter as the producing engine.
//
// Per CSAF 2.0, `tracking.generator.engine` describes "the engine that generated the CSAF
// document." The schema's own examples (`Red Hat rhsa-to-cvrf`, `Secvisogram`, `TVCE`) are
// exactly this class of tool — advisory converters and authoring tools. This program
// converts GHSA advisories into CSAF documents, so we ARE the engine, and populating this
// field is semantically correct rather than a workaround.
//
// Side note on the library / Go json interaction: gocsaf declares the field as
// `Generator *Generator ` + "`" + `json:"generator"` + "`" + ` (no `omitempty`), so a nil pointer would serialize
// as `"generator": null` — which the schema rejects (if the key is present, the value must
// be a valid object with `engine.name`). Emitting a real Generator here avoids that pitfall
// as well, but the primary reason is that the field genuinely describes this tool.
func getGenerator() *gocsaf.Generator {
	return &gocsaf.Generator{
		Engine: &gocsaf.Engine{
			Name:    utils.Ref("ghsa-to-csaf"),
			Version: utils.Ref("0.1.0"),
		},
	}
}

// getCurrentReleaseDate picks updated_at if newer else published_at
func getCurrentReleaseDate(adv *repository.Advisory) (current *string) {
	if adv.UpdatedAt != "" && adv.UpdatedAt > adv.PublishedAt {
		current = &adv.UpdatedAt
		return
	}
	current = &adv.PublishedAt
	return
}

// getAliases converts GHSA identifiers to CSAF aliases slice
func getAliases(identifiers []repository.Identifier) (aliases []*string) {
	aliases = make([]*string, len(identifiers))
	for i, id := range identifiers {
		aliases[i] = &id.Value
	}
	return
}

// getRevisionHistory synthesizes revisions from publish and update timestamps
// Note: GHSA does not provide a revision history, so we create one based on the publication date and the update date.
func getRevisionHistory(adv *repository.Advisory) (revisions gocsaf.Revisions) {
	var (
		n = atomic.Int32{}
	)
	// Published
	if adv.PublishedAt != "" {
		revNumber := gocsaf.RevisionNumber(strconv.Itoa(int(n.Add(1))))
		revisions = append(revisions, &gocsaf.Revision{
			Date:    &adv.PublishedAt,
			Number:  &revNumber,
			Summary: utils.Ref("Advisory published"),
		})
	}
	// Updated after publication (ISO 8601 strings are lexicographically sortable, so string comparison should work.)
	if adv.UpdatedAt != "" && adv.UpdatedAt != adv.PublishedAt && adv.UpdatedAt > adv.PublishedAt {
		revNumber := gocsaf.RevisionNumber(strconv.Itoa(int(n.Add(1))))
		revisions = append(revisions, &gocsaf.Revision{
			Date:    &adv.UpdatedAt,
			Number:  &revNumber,
			Summary: utils.Ref("Advisory updated"),
		})
	}
	return
}

// provideContactInformation builds a contact string from user profile/email
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
