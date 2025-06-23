package repository

// Advisory represents a GitHub Security Advisory on Repository level.
// It was created by converting the schema for a Repository (see repository_GHSA.json in the schemas folder).
// You can find it in the GitHub API documentation:
// https://docs.github.com/en/rest/security-advisories/repository-advisories?apiVersion=2022-11-28#list-repository-security-advisories
type Advisory struct {
	GhsaID          string           `json:"ghsa_id"`          // required
	CveID           string           `json:"cve_id"`           // required
	URL             string           `json:"url"`              // required
	HTMLURL         string           `json:"html_url"`         // required
	Summary         string           `json:"summary"`          // required
	Description     string           `json:"description"`      // required
	Severity        string           `json:"severity"`         // required
	Author          User             `json:"author"`           // required
	Publisher       User             `json:"publisher"`        // required
	Identifiers     []Identifier     `json:"identifiers"`      // required
	State           string           `json:"state"`            // required
	CreatedAt       string           `json:"created_at"`       // required
	UpdatedAt       string           `json:"updated_at"`       // required
	PublishedAt     string           `json:"published_at"`     // required
	ClosedAt        any              `json:"closed_at"`        // required
	WithdrawnAt     any              `json:"withdrawn_at"`     // required
	Submission      Submission       `json:"submission"`       // required
	Vulnerabilities []Vulnerability  `json:"vulnerabilities"`  // required
	CVSS            CVSS             `json:"cvss"`             // required
	CWEs            []CWE            `json:"cwes"`             // required
	CWEIds          []string         `json:"cwe_ids"`          // required
	Credits         []Credit         `json:"credits"`          // required
	CreditsDetailed []CreditDetailed `json:"credits detailed"` // required
	// Required. A list of users that collaborate on the advisory
	CollaboratingUsers []User `json:"collaborating_users"`
	// Required. A list of teams that collaborate on the advisory
	CollaboratingTeams []CollaborationTeam `json:"collaborating_teams"`
	// Required. A temporary private fork of the advisory's repository for collaborating on a fix.
	PrivateFork    Repository     `json:"private_fork"`
	CVSSSeverities CVSSSeverities `json:"cvss_severities"`
}

// Identifier represents an identification of the security advisory
type Identifier struct {
	// Required. The identifier value.
	Value string `json:"value"`
	// Required. The type of identifier, such as "CVE" or "GHSA".
	Type IdentifierType `json:"type"` // required
}

type IdentifierType string

var IdentifierValueCVE IdentifierType = "CVE"
var IdentifierValueGHSA IdentifierType = "GHSA"

// Submission represents the submission details of the advisory
type Submission struct {
	Accepted bool `json:"accepted"` // required
}

// Vulnerability represents a product affected by the advisory.
type Vulnerability struct {
	Package                Package  `json:"package"`                  // required
	VulnerableVersionRange string   `json:"vulnerable_version_range"` // required
	PatchedVersions        string   `json:"patched_versions"`         // required
	VulnerableFunctions    []string `json:"vulnerable_functions"`     // required
}

// Package represents a package affected by the vulnerability
type Package struct {
	Ecosystem string `json:"ecosystem"` // required
	Name      string `json:"name"`      // required
}

type CVSSSeverities struct {
	CVSSv3 CVSS `json:"cvss_v3"`
	CVSSv4 CVSS `json:"cvss_v4"`
}

// TODO(lebogg): Check if it exists in schema
// CVSS represents a CVSS score
type CVSS struct {
	VectorString string  `json:"vector_string"` // required
	Score        float64 `json:"score"`         // required
}

// CWE represents a Common Weakness Enumeration
type CWE struct {
	CWEID string `json:"cwe_id"` // required
	Name  string `json:"name"`   // required
}

// Credit represents a shortened credit given to a user for a security advisory. For detailed credits, use
// CreditDetailed.
type Credit struct {
	Login string `json:"login"`
	Type  string `json:"type"`
}

// CreditDetailed represents a credit given to a user for a repository security advisory
type CreditDetailed struct {
	User  User   `json:"user"`  // required
	Type  string `json:"type"`  // required
	State string `json:"state"` // required
}

// User represents a GitHub user
type User struct {
	Login             string `json:"login"`               // required
	ID                int64  `json:"id"`                  // required
	NodeID            string `json:"node_id"`             // required
	AvatarURL         string `json:"avatar_url"`          // required
	GravatarID        string `json:"gravatar_id"`         // required
	URL               string `json:"url"`                 // required
	HTMLURL           string `json:"html_url"`            // required
	FollowersURL      string `json:"followers_url"`       // required
	FollowingURL      string `json:"following_url"`       // required
	GistsURL          string `json:"gists_url"`           // required
	Starred_URL       string `json:"starred_url"`         // required
	SubscriptionsURL  string `json:"subscriptions_url"`   // required
	OrganizationsURL  string `json:"organizations_url"`   // required
	ReposURL          string `json:"repos_url"`           // required
	EventsURL         string `json:"events_url"`          // required
	ReceivedEventsURL string `json:"received_events_url"` // required
	Type              string `json:"type"`                // required
	SiteAdmin         bool   `json:"site_admin"`          // required
	Name              string `json:"name"`
	Email             string `json:"email"`
	StarredAt         string `json:"starred_at"`
	UserViewType      string `json:"user_view_type"`
}

// CollaborationTeam represents a team collaborating on the advisory.
type CollaborationTeam struct {
	ID                  int64      `json:"id"`               // required
	NodeID              string     `json:"node_id"`          // required
	Name                string     `json:"name"`             // required
	Slug                string     `json:"slug"`             // required
	Description         string     `json:"description"`      // required
	Permission          string     `json:"permission"`       // required
	URL                 string     `json:"url"`              // required
	HTMLURL             string     `json:"html_url"`         // required
	MembersURL          string     `json:"members_url"`      // required
	RepositoriesURL     string     `json:"repositories_url"` // required
	Parent              Team       `json:"parent"`           // required
	NotificationSetting string     `json:"notification_setting"`
	Permissions         Permission `json:"permissions"`
	Privacy             string     `json:"privacy"`
}

type Team struct {
	Id                  int    `json:"id"`               // required
	NodeID              string `json:"node_id"`          // required
	URL                 string `json:"url"`              // required
	MembersURL          string `json:"members_url"`      // required
	Name                string `json:"name"`             // required
	Description         string `json:"description"`      // required
	Permission          string `json:"permission"`       // required
	HTMLURL             string `json:"html_url"`         // required
	RepositoriesURL     string `json:"repositories_url"` // required
	Slug                string `json:"slug"`             // required
	Privacy             string `json:"privacy"`
	NotificationSetting string `json:"notification_setting"`
	LdapDn              string `json:"ldap_dn"`
}

type Permission struct {
	Pull     bool `json:"pull"`     // required
	Push     bool `json:"push"`     // required
	Admin    bool `json:"admin"`    // required
	Maintain bool `json:"maintain"` // required
	triage   bool `json:"triage"`   // required
}

// Repository represents a GitHub repository.
type Repository struct {
	ID               int64   `json:"id"`                // required
	NodeID           string  `json:"node_id"`           // required
	Name             string  `json:"name"`              // required
	FullName         string  `json:"full_name"`         // required
	Owner            User    `json:"owner"`             // required
	Private          bool    `json:"private"`           // required
	HTMLURL          string  `json:"html_url"`          // required
	Description      *string `json:"description"`       // required
	Fork             bool    `json:"fork"`              // required
	URL              string  `json:"url"`               // required
	ArchiveURL       string  `json:"archive_url"`       // required
	AssigneesURL     string  `json:"assignees_url"`     // required
	BlobsURL         string  `json:"blobs_url"`         // required
	BranchesURL      string  `json:"branches_url"`      // required
	CollaboratorsURL string  `json:"collaborators_url"` // required
	CommentsURL      string  `json:"comments_url"`      // required
	CommitsURL       string  `json:"commits_url"`       // required
	CompareURL       string  `json:"compare_url"`       // required
	ContentsURL      string  `json:"contents_url"`      // required
	ContributorsURL  string  `json:"contributors_url"`  // required
	DeploymentsURL   string  `json:"deployments_url"`   // required
	DownloadsURL     string  `json:"downloads_url"`     // required
	ForksURL         string  `json:"forks_url"`         // required
	GitCommitsURL    string  `json:"git_commits_url"`   // required
	GitRefsURL       string  `json:"git_refs_url"`      // required
	GitTagsURL       string  `json:"git_tags_url"`      // required
	IssueCommentURL  string  `json:"issue_comment_url"` // required
	IssuesEventsURL  string  `json:"issues_events_url"` // required
	IssuesURL        string  `json:"issues_url"`        // required
	KeysURL          string  `json:"keys_url"`          // required
	LabelsURL        string  `json:"labels_url"`        // required
	LanguagesURL     string  `json:"languages_url"`     // required
	MergesURL        string  `json:"merges_url"`        // required
	MilestonesURL    string  `json:"milestones_url"`    // required
	NotificationsURL string  `json:"notifications_url"` // required
	PullsURL         string  `json:"pulls_url"`         // required
	ReleasesURL      string  `json:"releases_url"`      // required
	StargazersURL    string  `json:"stargazers_url"`    // required
	StatusesURL      string  `json:"statuses_url"`      // required
	SubscribersURL   string  `json:"subscribers_url"`   // required
	SubscriptionURL  string  `json:"subscription_url"`  // required
	TagsURL          string  `json:"tags_url"`          // required
	TeamsURL         string  `json:"teams_url"`         // required
	TreesURL         string  `json:"trees_url"`         // required
	HooksURL         string  `json:"hooks_url"`         // required
}
