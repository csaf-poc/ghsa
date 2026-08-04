package converter

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	"github.com/gocsaf/csaf/v3/csaf"
)

// getVulnerabilities creates a single CSAF vulnerability from a GHSA advisory (first CWE only)
//
// Design Note on Vulnerability & CWE Mapping:
// A GHSA Advisory typically corresponds to a single CVE but may list multiple CWEs.
// But CSAF 2.0 enforces a strict 1:1 relationship between a Vulnerability object and a CWE.
//
// To adhere to this standard, this function creates a single CSAF Vulnerability object
// and maps only the *first* CWE from the GHSA list, treating it as the primary weakness.
// We intentionally avoid splitting the advisory into multiple Vulnerability objects (one per CWE)
// because that would incorrectly imply the existence of multiple distinct security flaws (CVEs)
// and result in unnecessary data duplication.
func getVulnerabilities(adv *repository.Advisory, pt *csaf.ProductTree) (vulnerabilities csaf.Vulnerabilities, err error) {
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
func getReferences(adv *repository.Advisory) (r csaf.References) {
	r = []*csaf.Reference{
		{
			ReferenceCategory: utils.Ref(string(csaf.CSAFReferenceCategoryExternal)),
			Summary:           utils.Ref("Advisory HTML URL"),
			URL:               utils.Ref(adv.HTMLURL),
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
func getProductStatusScoresAndNotes(adv *repository.Advisory, productIDs csaf.Products) (status *csaf.ProductStatus, scores []*csaf.Score, notes csaf.Notes) {
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

	if isV4Only(adv) {
		// v4 exists without a usable v3 source; keep score empty and document why.
		slog.Warn("GHSA advisory only provides CVSS v4: Omitting vulnerability score to avoid lossy v4-to-v3 conversion",
			slog.String("GHSA ID", adv.GhsaID))
		notes = csaf.Notes{
			&csaf.Note{
				NoteCategory: utils.Ref(csaf.CSAFNoteCategoryDescription),
				Title:        utils.Ref("CVSS conversion limitation"),
				Text:         utils.Ref("The advisory provides only CVSS v4 data. This converter currently exports only CVSS v3 vulnerability scores in CSAF 2.0, so the score was omitted to avoid lossy conversion."),
			},
		}
	}

	return
}

// getVulnerabilityIDs returns vulnerability IDs referencing the GHSA ID
func getVulnerabilityIDs(adv *repository.Advisory) (ids csaf.VulnerabilityIDs) {
	ids = []*csaf.VulnerabilityID{
		{
			SystemName: utils.Ref("GitHub Security Advisory"),
			Text:       utils.Ref(adv.GhsaID),
		},
	}
	return
}

// getCWE maps the first GHSA CWE to CSAF CWE
func getCWE(adv *repository.Advisory) (cwe *csaf.CWE) {
	if len(adv.CWEs) > 0 {
		// We map the first CWE found in the GHSA as the primary one
		cwe = &csaf.CWE{
			ID:   utils.Ref(csaf.WeaknessID(adv.CWEs[0].CWEID)),
			Name: utils.Ref(adv.CWEs[0].Name),
		}
	}
	return
}

// getCVE returns the CVE identifier if present
func getCVE(adv *repository.Advisory) (cve *csaf.CVE) {
	if adv.CveID != "" {
		cve = utils.Ref(csaf.CVE(adv.CveID))
	}
	return
}

// convertScores converts GHSA CVSS into CSAF CVSS v3 only.
//
// Source precedence:
// 1) GHSA cvss_severities.cvss_v3 (preferred explicit source)
// 2) GHSA legacy cvss (backward compatibility)
// 3) otherwise no score
//
// Safety rule:
// We only accept vectors that clearly declare CVSS 3.0/3.1. Any other vector
// version is rejected to avoid accidentally placing non-v3 semantics into CSAF cvss_v3.
func convertScores(adv *repository.Advisory, productIDs csaf.Products) (*csaf.Score, error) {
	// Prefer CVSS v3 from CVSSSeverities
	var vector string
	var scoreVal float64

	if adv.CVSSSeverities.CVSSv3.VectorString != "" {
		vector = adv.CVSSSeverities.CVSSv3.VectorString
		scoreVal = adv.CVSSSeverities.CVSSv3.Score
	} else if adv.CVSS.VectorString != "" {
		// Fallback to legacy CVSS field
		vector = adv.CVSS.VectorString
		scoreVal = adv.CVSS.Score
	} else {
		// No v3-compatible score source. CVSS v4-only cases are handled via notes/logging.
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
func isV4Only(adv *repository.Advisory) bool {
	if adv.CVSSSeverities.CVSSv3.VectorString != "" || adv.CVSS.VectorString != "" {
		return false
	}

	v4 := adv.CVSSSeverities.CVSSv4
	// Check if v4 has meaningful data
	return strings.TrimSpace(v4.VectorString) != "" || v4.Score > 0
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
// Keep each remediation aligned with its corresponding product so the
// patched version remains product-specific instead of being flattened into
// a single advisory-wide string.
func getRemediations(adv *repository.Advisory, productIDs csaf.Products) csaf.Remediations {
	var remediations csaf.Remediations

	for i, vuln := range adv.Vulnerabilities {
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
