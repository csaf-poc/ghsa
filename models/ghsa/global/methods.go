package global

import (
	"time"

	"github.com/csaf-poc/ghsa/models/ghsa"
)

func (a *Advisory) GetGhsaID() string { return a.ID }
func (a *Advisory) GetCveID() string {
	if a.CveID == nil {
		return ""
	}
	return *a.CveID
}
func (a *Advisory) GetHTMLURL() string { return a.HTMLURL }
func (a *Advisory) GetSummary() string { return a.Summary }
func (a *Advisory) GetDescription() string {
	if a.Description == nil {
		return ""
	}
	return *a.Description
}
func (a *Advisory) GetSeverity() string        { return a.Severity }
func (a *Advisory) GetPublishedAt() *time.Time { return &a.PublishedAt }
func (a *Advisory) GetUpdatedAt() *time.Time   { return &a.UpdatedAt }

func (a *Advisory) GetIdentifiers() []ghsa.CommonIdentifier {
	ids := make([]ghsa.CommonIdentifier, len(a.Identifiers))
	for i, id := range a.Identifiers {
		ids[i] = ghsa.CommonIdentifier{
			Type:  id.Type,
			Value: id.Value,
		}
	}
	return ids
}

func (a *Advisory) GetCVSSv3() (string, float64) {
	if a.CVSSSeverities != nil && a.CVSSSeverities.CVSSv3 != nil {
		var vector string
		var score float64
		if a.CVSSSeverities.CVSSv3.VectorString != nil {
			vector = *a.CVSSSeverities.CVSSv3.VectorString
		}
		if a.CVSSSeverities.CVSSv3.Score != nil {
			score = *a.CVSSSeverities.CVSSv3.Score
		}
		return vector, score
	}
	return "", 0
}

func (a *Advisory) GetCVSSv4() (string, float64) {
	if a.CVSSSeverities != nil && a.CVSSSeverities.CVSSv4 != nil {
		var vector string
		var score float64
		if a.CVSSSeverities.CVSSv4.VectorString != nil {
			vector = *a.CVSSSeverities.CVSSv4.VectorString
		}
		if a.CVSSSeverities.CVSSv4.Score != nil {
			score = *a.CVSSSeverities.CVSSv4.Score
		}
		return vector, score
	}
	return "", 0
}

func (a *Advisory) GetCWEs() []ghsa.CommonCWE {
	cwes := make([]ghsa.CommonCWE, len(a.CWEs))
	for i, c := range a.CWEs {
		cwes[i] = ghsa.CommonCWE{
			CWEID: c.CWEID,
			Name:  c.Name,
		}
	}
	return cwes
}

func (a *Advisory) GetVulnerabilities() []ghsa.CommonVulnerability {
	vulns := make([]ghsa.CommonVulnerability, len(a.Vulnerabilities))
	for i, v := range a.Vulnerabilities {
		var packageName string
		if v.Package != nil && v.Package.Name != nil {
			packageName = *v.Package.Name
		}
		var ecosystem string
		if v.Package != nil {
			ecosystem = v.Package.Ecosystem
		}
		var versionRange string
		if v.VulnerableVersionRange != nil {
			versionRange = *v.VulnerableVersionRange
		}
		var patchedVersions string
		if v.FirstPatchedVersion != nil {
			patchedVersions = *v.FirstPatchedVersion
		}

		vulns[i] = ghsa.CommonVulnerability{
			PackageName:            packageName,
			Ecosystem:              ecosystem,
			VulnerableVersionRange: versionRange,
			PatchedVersions:        patchedVersions,
		}
	}
	return vulns
}

func (a *Advisory) GetCredits() []ghsa.CommonCredit {
	credits := make([]ghsa.CommonCredit, len(a.Credits))
	for i, c := range a.Credits {
		var name string
		if c.User.Name != nil {
			name = *c.User.Name
		}
		credits[i] = ghsa.CommonCredit{
			Login: c.User.Login,
			Name:  name,
			URL:   c.User.HTMLURL,
			Type:  c.Type,
		}
	}
	return credits
}

func (a *Advisory) GetPublisher() *ghsa.CommonUser {
	// Global advisories don't have a specific publisher in the JSON, but they are published by GitHub.
	return &ghsa.CommonUser{
		Login:   "github",
		HTMLURL: "https://github.com",
	}
}

func (a *Advisory) GetEPSS() *ghsa.CommonEPSS {
	if a.EPSS == nil {
		return nil
	}
	var percentage, percentile float64
	if a.EPSS.Percentage != nil {
		percentage = *a.EPSS.Percentage
	}
	if a.EPSS.Percentile != nil {
		percentile = *a.EPSS.Percentile
	}
	return &ghsa.CommonEPSS{
		Percentage: percentage,
		Percentile: percentile,
	}
}
