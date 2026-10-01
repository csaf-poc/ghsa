package converter

import (
	"testing"
	"time"

	"github.com/csaf-poc/ghsa/internal/config"
	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

func Test_getRevisionHistory(t *testing.T) {
	pubAt, _ := time.Parse(time.RFC3339, "2024-01-02T03:04:05Z")
	updAt, _ := time.Parse(time.RFC3339, "2024-02-02T03:04:05Z")
	adv := &repository.Advisory{
		PublishedAt: &pubAt,
		UpdatedAt:   &updAt,
	}
	revs := getRevisionHistory(adv)
	if len(revs) != 2 {
		t.Fatalf("want 2 revisions, got %d", len(revs))
	}
	if revs[0].Summary == nil || *revs[0].Summary != "Advisory published" {
		t.Errorf("first revision summary = %v, want 'Advisory published'", revs[0].Summary)
	}
	if revs[1].Summary == nil || *revs[1].Summary != "Advisory updated" {
		t.Errorf("second revision summary = %v, want 'Advisory updated'", revs[1].Summary)
	}
}

func Test_getCategoryAndVersion(t *testing.T) {
	cat := getCategory()
	if cat == nil || *cat != gocsaf.DocumentCategory(documentCategory) {
		t.Errorf("category = %v, want %v", cat, documentCategory)
	}
	ver := getVersion()
	if ver == nil || *ver != gocsaf.CSAFVersion20 {
		t.Errorf("version = %v, want CSAF 2.0", ver)
	}
}

func Test_getAcknowledgements_PrefersDetailedCredits(t *testing.T) {
	adv := &repository.Advisory{
		CreditsDetailed: []repository.CreditDetailed{
			{
				User: repository.User{
					Login:            "detailed-user",
					Name:             utils.Ref("Detailed User"),
					HTMLURL:          "https://github.com/detailed-user",
					OrganizationsURL: "https://api.github.com/users/detailed-user/orgs",
				},
				Type: "REPORTER",
			},
		},
		Credits: []repository.Credit{
			{Login: "fallback-user", Type: "FINDER"},
		},
	}

	ack := getAcknowledgements(adv)
	if ack == nil || len(*ack) != 1 {
		t.Fatalf("expected one acknowledgement from detailed credits, got %v", ack)
	}
	if (*ack)[0].Names == nil || len((*ack)[0].Names) != 1 || *(*ack)[0].Names[0] != "Detailed User" {
		t.Fatalf("unexpected acknowledgement name: %#v", (*ack)[0].Names)
	}
}

func Test_getAcknowledgements_FallsBackToCredits(t *testing.T) {
	adv := &repository.Advisory{
		CreditsDetailed: nil,
		Credits: []repository.Credit{
			{Login: "fallback-user", Type: "REPORTER"},
		},
	}

	ack := getAcknowledgements(adv)
	if ack == nil || len(*ack) != 1 {
		t.Fatalf("expected one acknowledgement from fallback credits, got %v", ack)
	}
	if (*ack)[0].Names == nil || len((*ack)[0].Names) != 1 || *(*ack)[0].Names[0] != "fallback-user" {
		t.Fatalf("unexpected fallback acknowledgement name: %#v", (*ack)[0].Names)
	}
	if (*ack)[0].Summary == nil || *(*ack)[0].Summary != "Reported the vulnerability" {
		t.Fatalf("unexpected fallback acknowledgement summary: %#v", (*ack)[0].Summary)
	}
}

func Test_getPublisher_RepositoryDefaultsToOwnerAndOther(t *testing.T) {
	adv := &repository.Advisory{
		HTMLURL:   "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
		Publisher: &repository.User{Login: "oxisto", HTMLURL: "https://github.com/oxisto"},
	}

	p := getPublisher(adv.GetPublisher(), nil)
	if *p.Name != "golang-jwt" || *p.Namespace != "https://github.com/golang-jwt" {
		t.Errorf("got name=%v namespace=%v, want golang-jwt / https://github.com/golang-jwt", *p.Name, *p.Namespace)
	}
	if *p.Category != gocsaf.CSAFCategoryOther {
		t.Errorf("category = %v, want other", *p.Category)
	}
	if p.IssuingAuthority != nil {
		t.Errorf("issuing authority = %v, want unset", *p.IssuingAuthority)
	}
}

func Test_getPublisher_ConfigOverrides(t *testing.T) {
	adv := &repository.Advisory{
		HTMLURL: "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
	}
	override := &config.Publisher{
		Category:         "vendor",
		Name:             "golang-jwt maintainers",
		IssuingAuthority: "Maintained by the golang-jwt project",
	}

	p := getPublisher(adv.GetPublisher(), override)
	if *p.Category != gocsaf.CSAFCategoryVendor || *p.Name != "golang-jwt maintainers" {
		t.Errorf("got category=%v name=%v, want overrides", *p.Category, *p.Name)
	}
	// Namespace isn't overridden and must stay derived.
	if *p.Namespace != "https://github.com/golang-jwt" {
		t.Errorf("namespace = %v, want derived value", *p.Namespace)
	}
	if p.IssuingAuthority == nil || *p.IssuingAuthority != override.IssuingAuthority {
		t.Errorf("issuing authority = %v, want %q", p.IssuingAuthority, override.IssuingAuthority)
	}
}
