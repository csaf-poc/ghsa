package ghsa

import "time"

// GHSAAdvisory defines a common interface for both repository and global GHSA advisories.
type GHSAAdvisory interface {
	GetGhsaID() string
	GetCveID() string
	GetHTMLURL() string
	GetSummary() string
	GetDescription() string
	GetSeverity() string
	GetPublishedAt() *time.Time
	GetUpdatedAt() *time.Time
	GetIdentifiers() []CommonIdentifier
	GetCVSSv3() (vector string, score float64)
	GetCVSSv4() (vector string, score float64)
	GetCWEs() []CommonCWE
	GetVulnerabilities() []CommonVulnerability
	GetCredits() []CommonCredit
	GetPublisher() *CommonUser
	GetEPSS() *CommonEPSS
}

// CommonEPSS represents Exploit Prediction Scoring System data.
type CommonEPSS struct {
	Percentage float64
	Percentile float64
}

// CommonIdentifier represents a GHSA identifier (CVE or GHSA ID).
type CommonIdentifier struct {
	Type  string
	Value string
}

// CommonCWE represents a Common Weakness Enumeration.
type CommonCWE struct {
	CWEID string
	Name  string
}

// CommonVulnerability represents an affected package and version ranges.
type CommonVulnerability struct {
	PackageName            string
	Ecosystem              string
	VulnerableVersionRange string
	PatchedVersions        string
}

// CommonCredit represents a credit given to a user.
type CommonCredit struct {
	Login string
	Name  string
	URL   string
	Type  string
}

// CommonUser represents a GitHub user.
type CommonUser struct {
	Login   string
	HTMLURL string
	Email   string
}
