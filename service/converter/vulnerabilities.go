package converter

import (
	"fmt"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	"github.com/gocsaf/csaf/v3/csaf"
)

// TODO(lebogg): Implement
// getVulnerabilities converts a GHSA Advisory into a CSAF Vulnerabilities list.
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
	productStatus, scores := getProductStatusAndScores(adv, productIDs)
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
		Notes:            nil, // The notes are already included in the document which describes the advisory as a whole.
		Flags:            nil, // GHSA lacks VEX justification data
		ReleaseDate:      nil, // Finding out when this "was originally released into the wild" requires extensive analysis
		Threats:          nil, // GHSA lacks detailed threat intelligence beyond severity
		Title:            nil, // Document title already covers the advisory; per-vulnerability title would duplicate
	}

	vulnerabilities = append(vulnerabilities, v)
	return
}

// getProductIDs returns a list of ProductIDs from the ProductTree.
func getProductIDs(pt *csaf.ProductTree) (products []*csaf.ProductID) {
	for _, p := range *pt.FullProductNames {
		products = append(products, p.ProductID)
	}
	return
}

// getReferences returns a list of references with one item referencing to the GHSA advisory HTML page.
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

// getProductStatusAndScores returns a ProductStatus and a list of Scores based on the GHSA advisory.
func getProductStatusAndScores(adv *repository.Advisory, productIDs csaf.Products) (status *csaf.ProductStatus, scores []*csaf.Score) {
	if len(productIDs) > 0 {
		// We assume that all products associated with this advisory in the tree are "Known Affected"
		// unless specific status logic (e.g. fixed/patched separation) is implemented upstream.
		status = &csaf.ProductStatus{
			KnownAffected: &productIDs,
		}

		// Scores
		score, err := convertScores(adv, productIDs)
		if err == nil && score != nil {
			scores = []*csaf.Score{score}
		}
	}
	return
}

// getVulnerabilityIDs returns a list of VulnerabilityIDs with one item referencing to the GHSA advisory ID.
func getVulnerabilityIDs(adv *repository.Advisory) (ids csaf.VulnerabilityIDs) {
	ids = []*csaf.VulnerabilityID{
		{
			SystemName: utils.Ref("GitHub Security Advisory"),
			Text:       utils.Ref(adv.GhsaID),
		},
	}
	return
}

// getCWE extracts CWE information from the GHSA advisory. We use the first CWE found in the list, assuming it is the
// primary one (CSAF only provides one CWE per Vulnerability object).
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

// getCVE extracts CVE information from the GHSA advisory.
func getCVE(adv *repository.Advisory) (cve *csaf.CVE) {
	if adv.CveID != "" {
		cve = utils.Ref(csaf.CVE(adv.CveID))
	}
	return
}

// convertScores converts the GHSA advisory scores into a CSAF Score object.
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
		return nil, nil
	}

	// Determine CVSS version from vector string
	var version csaf.CVSSVersion3
	if strings.HasPrefix(vector, "CVSS:3.1") {
		version = csaf.CVSSVersion31
	} else if strings.HasPrefix(vector, "CVSS:3.0") {
		version = csaf.CVSSVersion30
	} else {
		// Skip unsupported versions (e.g. v2 or v4 if not supported by CSAF types yet)
		// CSAF 2.0 mainly targets CVSS 3.x
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

// calculateSeverity returns the CVSS3 severity based on score.
func calculateSeverity(score float64) csaf.CVSS3Severity {
	switch {
	case score >= 9.0:
		return "CRITICAL"
	case score >= 7.0:
		return "HIGH"
	case score >= 4.0:
		return "MEDIUM"
	case score > 0.0:
		return "LOW"
	default:
		return "NONE"
	}
}

// getRemediations extracts patch information from the GHSA advisory.
func getRemediations(adv *repository.Advisory, productIDs csaf.Products) csaf.Remediations {
	var remediations csaf.Remediations
	var patchedVersions []string

	for _, vuln := range adv.Vulnerabilities {
		if vuln.PatchedVersions != "" {
			patchedVersions = append(patchedVersions, vuln.PatchedVersions)
		}
	}

	if len(patchedVersions) > 0 && len(productIDs) > 0 {
		details := fmt.Sprintf("Upgrade to version: %s", strings.Join(patchedVersions, ", "))
		remediations = append(remediations, &csaf.Remediation{
			Category:   utils.Ref(csaf.CSAFRemediationCategoryVendorFix),
			Details:    utils.Ref(details),
			ProductIds: &productIDs,
		})
	}

	return remediations
}
