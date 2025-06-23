package global

import (
	"time"
)

// Advisory represents a global GitHub Security Advisory.
// It was created with a global GHSA example (see GHSA-cpj6-fhp6-mr6j.json in examples).
type Advisory struct {
	ID                    string              `json:"ghsa_id"`
	Credits               []Credit            `json:"credits"`
	CveID                 string              `json:"cve_id"`
	CVSS                  CVSS                `json:"cvss"`
	CVSSSeverities        CVSSSeverities      `json:"cvss_severities"`
	CWEs                  []CWE               `json:"cwes"`
	Description           string              `json:"description"`
	EPSP                  EPSP                `json:"epss"`
	GithubReviewedAt      time.Time           `json:"github_reviewed_at"`
	HTMLURL               string              `json:"html_url"`
	Identifiers           Identifier          `json:"identifiers"`
	NVDPublishedAt        time.Time           `json:"nvd_published_at"`
	PublishedAt           time.Time           `json:"published_at"`
	References            []string            `json:"references"`
	RepositoryAdvisoryURL string              `json:"repository_advisory_url"`
	Severity              string              `json:"severity"`
	SourceCodeLocation    string              `json:"source_code_location"`
	Summary               string              `json:"summary"`
	Type                  string              `json:"type"`
	UpdatedAt             time.Time           `json:"updated_at"`
	URL                   string              `json:"url"`
	Vulnerabilities       []GHSAVulnerability `json:"vulnerabilities"`
	WithdrawnAt           *time.Time          `json:"withdrawn_at,omitempty"`
}

type Credit struct {
	Type string `json:"type"`
	User User   `json:"user"`
}

type User struct {
	Login             string `json:"login"`
	ID                int    `json:"id"`
	HTMLURL           string `json:"html_url"`
	AvatarURL         string `json:"avatar_url"`
	EventsURL         string `json:"events_url"`          // only for global GHSA
	FollowersURL      string `json:"followers_url"`       // only for global GHSA
	FollowingURL      string `json:"following_url"`       // only for global GHSA
	GistsURL          string `json:"gists_url"`           // only for global GHSA
	GravatarID        string `json:"gravatar_id"`         // only for global GHSA
	NodeID            string `json:"node_id"`             // only for global GHSA
	OrganizationsURL  string `json:"organizations_url"`   // only for global GHSA
	ReceivedEventsURL string `json:"received_events_url"` // only for global GHSA
	ReposURL          string `json:"repos_url"`           // only for global GHSA
	SiteAdmin         bool   `json:"site_admin"`          // only for global GHSA
	StarredURL        string `json:"starred_url"`         // only for global GHSA
	SubscriptionsURL  string `json:"subscriptions_url"`   // only for global GHSA
	Type              string `json:"type"`                // only for global GHSA
	URL               string `json:"url"`                 // only for global GHSA
	UserViewType      string `json:"user_view_type"`      // only for global GHSA
}

type CVSS struct {
	Score        float64 `json:"score"`
	VectorString string  `json:"vector_string"`
}

type CVSSSeverities struct {
	CVSSv3 CVSS `json:"cvss_v3"`
	CVSSv4 CVSS `json:"cvss_v4"`
}

type CWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

type EPSP struct {
	Percentage float64 `json:"percentage"`
	Percentile float64 `json:"percentile"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type GHSAVulnerability struct {
	FirstPatchedVersion    string   `json:"first_patched_version"`
	Package                Package  `json:"package"`
	VulnerableFunctions    []string `json:"vulnerable_functions"`
	VulnerableVersionRange string   `json:"vulnerable_version_range"`
}

type Package struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
}
