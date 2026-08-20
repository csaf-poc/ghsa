package converter

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa"
	"github.com/gocsaf/csaf/v3/csaf"
)

// getVulnerabilities creates a single CSAF vulnerability from a GHSA advisory (first CWE only)
func getVulnerabilities(adv ghsa.GHSAAdvisory, pt *csaf.ProductTree) (vulnerabilities csaf.Vulnerabilities, err error) {
	productIDs := getProductIDs(pt)
	productStatus, scores, notes := getProductStatusScoresAndNotes(adv, productIDs)
	v := &csaf.Vulnerability{
		CVE:              getCVE(adv),
		CWE:              getCWE(adv),
		IDs:              getVulnerabilityIDs(adv),
		ProductStatus:    productStatus,
		References:       getReferences(adv),
		Remediations:     getRemediations(adv, productIDs),
		Scores:           scores,
		Acknowledgements: nil, // The acknowledgements are already included in the document (CreditsDetailed applies to the entire advisory)
		DiscoveryDate:    nil, // GHSA doesn't provide this distinct from publication dates
		Involvements:     nil, // Involvements are already included in the document, see Publisher and Tracking
		Notes:            notes,
		Flags:            nil, // GHSA lacks VEX justification data
		ReleaseDate:      nil, // Finding out when this "was originally released into the wild" requires extensive analysis
		Threats:          nil, // GHSA lacks detailed threat intelligence beyond severity
		Title:            nil, // Document title already covers the advisory; per-vulnerability title would duplicate
	}

	vulnerabilities = append(vulnerabilities, v)
	return
}

// getProductIDs extracts product IDs from the product tree
func getProductIDs(pt *csaf.ProductTree) (products []*csaf.ProductID) {
	for _, p := range *pt.FullProductNames {
		products = append(products, p.ProductID)
	}
	return
}

// getReferences returns a CSAF references slice with the advisory HTML page
func getReferences(adv ghsa.GHSAAdvisory) (r csaf.References) {
	r = []*csaf.Reference{
		{
			ReferenceCategory: utils.Ref(string(csaf.CSAFReferenceCategoryExternal)),
			Summary:           utils.Ref("Advisory HTML URL"),
			URL:               utils.Ref(adv.GetHTMLURL()),
		},
	}
	return
}

// getProductStatusScoresAndNotes derives three vulnerability facets from one place:
// - product status (known_affected)
// - score entries (only when we can produce CSAF CVSS v3)
// - conversion notes (when GHSA has meaningful v4-only data)
//
// Design intent:
// - Keep score emission strict (no lossy v4->v3 projection).
// - Keep operators informed: v4-only advisories generate both a log warning and a CSAF note.
// - Keep output clean when v4 is effectively empty (no vector and score 0): treat as absent, no note.
func getProductStatusScoresAndNotes(adv ghsa.GHSAAdvisory, productIDs csaf.Products) (status *csaf.ProductStatus, scores []*csaf.Score, notes csaf.Notes) {
	if len(productIDs) > 0 {
		// We assume that all products associated with this advisory in the tree are "Known Affected"
		// unless specific status logic (e.g. fixed/patched separation) is implemented upstream.
		status = &csaf.ProductStatus{
			KnownAffected: &productIDs,
		}

		// Scores: generated only for valid CVSS v3 vectors (see convertScores).
		score, err := convertScores(adv, productIDs)
		if err == nil && score != nil {
			scores = []*csaf.Score{score}
		}
	}

	if epss := adv.GetEPSS(); epss != nil {
		notes = append(notes, &csaf.Note{
			NoteCategory: utils.Ref(csaf.CSAFNoteCategoryOther),
			Title:        utils.Ref("EPSS Score"),
			Text:         utils.Ref(fmt.Sprintf("Exploit Prediction Scoring System (EPSS) score: %.5f (percentile: %.5f)", epss.Percentage, epss.Percentile)),
		})
	}

	if isV4Only(adv) {
		// v4 exists without a usable v3 source; keep score empty and document why.
		slog.Warn("GHSA advisory only provides CVSS v4: Omitting vulnerability score to avoid lossy v4-to-v3 conversion",
			slog.String("GHSA ID", adv.GetGhsaID()))
		notes = append(notes, &csaf.Note{
			NoteCategory: utils.Ref(csaf.CSAFNoteCategoryDescription),
			Title:        utils.Ref("CVSS conversion limitation"),
			Text:         utils.Ref("The advisory provides only CVSS v4 data. This converter currently exports only CVSS v3 vulnerability scores in CSAF 2.0, so the score was omitted to avoid lossy conversion."),
		})
	}

	return
}

// getVulnerabilityIDs returns vulnerability IDs referencing the GHSA ID
func getVulnerabilityIDs(adv ghsa.GHSAAdvisory) (ids csaf.VulnerabilityIDs) {
	ids = []*csaf.VulnerabilityID{
		{
			SystemName: utils.Ref("GitHub Security Advisory"),
			Text:       utils.Ref(adv.GetGhsaID()),
		},
	}
	return
}

// getCWE maps the first GHSA CWE to CSAF CWE
func getCWE(adv ghsa.GHSAAdvisory) (cwe *csaf.CWE) {
	cwes := adv.GetCWEs()
	if len(cwes) > 0 {
		// We map the first CWE found in the GHSA as the primary one
		cwe = &csaf.CWE{
			ID:   utils.Ref(csaf.WeaknessID(cwes[0].CWEID)),
			Name: utils.Ref(cwes[0].Name),
		}
	}
	return
}

// getCVE returns the CVE identifier if present
func getCVE(adv ghsa.GHSAAdvisory) (cve *csaf.CVE) {
	cveID := adv.GetCveID()
	if cveID != "" {
		cve = utils.Ref(csaf.CVE(cveID))
	}
	return
}

// convertScores converts GHSA CVSS into CSAF CVSS v3 only.
func convertScores(adv ghsa.GHSAAdvisory, productIDs csaf.Products) (*csaf.Score, error) {
	vector, scoreVal := adv.GetCVSSv3()
	if vector == "" {
		return nil, nil
	}

	// Determine CVSS version from vector string
	var version csaf.CVSSVersion3
	if strings.HasPrefix(vector, "CVSS:3.1") {
		version = csaf.CVSSVersion31
	} else if strings.HasPrefix(vector, "CVSS:3.0") {
		version = csaf.CVSSVersion30
	} else {
		// Reject non-3.x vectors (e.g., v2/v4) instead of coercing them into cvss_v3.
		return nil, fmt.Errorf("unsupported or invalid CVSS vector: %s", vector)
	}

	return &csaf.Score{
		Products: &productIDs,
		CVSS3: &csaf.CVSS3{
			Version:      &version,
			VectorString: (*csaf.CVSS3VectorString)(&vector),
			BaseScore:    &scoreVal,
			BaseSeverity: utils.Ref(calculateSeverity(scoreVal)),
		},
	}, nil
}

// isV4Only determines if an advisory contains only CVSS v4 data
func isV4Only(adv ghsa.GHSAAdvisory) bool {
	v3Vector, _ := adv.GetCVSSv3()
	if v3Vector != "" {
		return false
	}

	v4Vector, v4Score := adv.GetCVSSv4()
	// Check if v4 has meaningful data
	return strings.TrimSpace(v4Vector) != "" || v4Score > 0
}

// calculateSeverity maps a numeric CVSS score to a severity string according to the CVSS v3.1 specification
func calculateSeverity(score float64) csaf.CVSS3Severity {
	switch {
	case score >= 9.0:
		return csaf.CVSS3SeverityCritical
	case score >= 7.0:
		return csaf.CVSS3SeverityHigh
	case score >= 4.0:
		return csaf.CVSS3SeverityMedium
	case score > 0.0:
		return csaf.CVSS3SeverityLow
	default:
		return csaf.CVSS3SeverityNone
	}
}

// getRemediations builds remediation entries using patched versions.
func getRemediations(adv ghsa.GHSAAdvisory, productIDs csaf.Products) csaf.Remediations {
	var remediations csaf.Remediations
	vulns := adv.GetVulnerabilities()

	for i, vuln := range vulns {
		if vuln.PatchedVersions == "" || i >= len(productIDs) || productIDs[i] == nil {
			continue
		}

		details := fmt.Sprintf("Upgrade to version: %s", vuln.PatchedVersions)
		productID := csaf.Products{productIDs[i]}
		remediations = append(remediations, &csaf.Remediation{
			Category:   utils.Ref(csaf.CSAFRemediationCategoryVendorFix),
			Details:    utils.Ref(details),
			ProductIds: &productID,
		})
	}

	return remediations
}
