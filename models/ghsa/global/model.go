package global

import (
	"time"
)

// Advisory represents a global GitHub Security Advisory.
// It was created with a global GHSA example (see GHSA-cpj6-fhp6-mr6j.json in examples).
type Advisory struct {
	ID                    string              `json:"ghsa_id"`
	Credits               []Credit            `json:"credits"`
	CveID                 *string             `json:"cve_id"`
	CVSSSeverities        *CVSSSeverities     `json:"cvss_severities,omitempty"`
	CWEs                  []CWE               `json:"cwes"`
	Description           *string             `json:"description"`
	EPSS                  *EPSS               `json:"epss,omitempty"`
	GithubReviewedAt      *time.Time          `json:"github_reviewed_at"`
	HTMLURL               string              `json:"html_url"`
	Identifiers           []Identifier        `json:"identifiers"`
	NVDPublishedAt        *time.Time          `json:"nvd_published_at"`
	PublishedAt           time.Time           `json:"published_at"`
	References            []string            `json:"references"`
	RepositoryAdvisoryURL *string             `json:"repository_advisory_url"`
	Severity              string              `json:"severity"`
	SourceCodeLocation    *string             `json:"source_code_location"`
	Summary               string              `json:"summary"`
	Type                  string              `json:"type"`
	UpdatedAt             time.Time           `json:"updated_at"`
	URL                   string              `json:"url"`
	Vulnerabilities       []GHSAVulnerability `json:"vulnerabilities"`
	WithdrawnAt           *time.Time          `json:"withdrawn_at"`
}

type Credit struct {
	Type string `json:"type"`
	User User   `json:"user"`
}

type User struct {
	Login             string  `json:"login"`
	ID                int64   `json:"id"`
	HTMLURL           string  `json:"html_url"`
	AvatarURL         string  `json:"avatar_url"`
	EventsURL         string  `json:"events_url"`
	FollowersURL      string  `json:"followers_url"`
	FollowingURL      string  `json:"following_url"`
	GistsURL          string  `json:"gists_url"`
	GravatarID        *string `json:"gravatar_id"`
	NodeID            string  `json:"node_id"`
	OrganizationsURL  string  `json:"organizations_url"`
	ReceivedEventsURL string  `json:"received_events_url"`
	ReposURL          string  `json:"repos_url"`
	SiteAdmin         bool    `json:"site_admin"`
	StarredURL        string  `json:"starred_url"`
	SubscriptionsURL  string  `json:"subscriptions_url"`
	Type              string  `json:"type"`
	URL               string  `json:"url"`
	UserViewType      *string `json:"user_view_type,omitempty"`
	Name              *string `json:"name,omitempty"`
	Email             *string `json:"email,omitempty"`
	StarredAt         *string `json:"starred_at,omitempty"`
}

type CVSS struct {
	Score        *float64 `json:"score"`
	VectorString *string  `json:"vector_string"`
}

type CVSSSeverities struct {
	CVSSv3 *CVSS `json:"cvss_v3,omitempty"`
	CVSSv4 *CVSS `json:"cvss_v4,omitempty"`
}

type CWE struct {
	CWEID string `json:"cwe_id"`
	Name  string `json:"name"`
}

type EPSS struct {
	Percentage *float64 `json:"percentage,omitempty"`
	Percentile *float64 `json:"percentile,omitempty"`
}

type Identifier struct {
	Type  string `json:"type"`
	Value string `json:"value"`
}

type GHSAVulnerability struct {
	FirstPatchedVersion    *string  `json:"first_patched_version"`
	Package                *Package `json:"package"`
	VulnerableFunctions    []string `json:"vulnerable_functions"`
	VulnerableVersionRange *string  `json:"vulnerable_version_range"`
}
type Package struct {
	Ecosystem string  `json:"ecosystem"`
	Name      *string `json:"name"`
}
