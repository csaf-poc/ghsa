package converter

import (
	"testing"

	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

func Test_ToCSAF_Minimal(t *testing.T) {
	adv := &repository.Advisory{
		GhsaID:      "GHSA-abc",
		Summary:     "Test advisory",
		Description: "Desc",
		Severity:    "HIGH",
		Publisher:   repository.User{Login: "user", HTMLURL: "https://github.com/user"},
		Identifiers: []repository.Identifier{{Value: "GHSA-abc"}},
		PublishedAt: "2024-01-02T03:04:05Z",
		UpdatedAt:   "2024-01-03T03:04:05Z",
		Vulnerabilities: []repository.Vulnerability{{
			Package:                repository.Package{Ecosystem: "Go", Name: "github.com/acme/lib/v2"},
			VulnerableVersionRange: "<=1.2.3",
		}},
	}
	csafAdv, err := ToCSAF(adv)
	if err != nil {
		t.Fatalf("ToCSAF returned error: %v", err)
	}
	if csafAdv.Document == nil || csafAdv.ProductTree == nil || len(csafAdv.Vulnerabilities) != 1 {
		t.Errorf("unexpected advisory assembly: doc=%v, pt=%v, vulns=%d", csafAdv.Document, csafAdv.ProductTree, len(csafAdv.Vulnerabilities))
	}
}
