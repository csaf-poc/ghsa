package converter

import (
	"encoding/json"
	"os"
	"testing"
	"time"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/global"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

func Test_ToCSAF_Minimal(t *testing.T) {
	pubDate, _ := time.Parse(time.RFC3339, "2024-01-02T03:04:05Z")
	updDate, _ := time.Parse(time.RFC3339, "2024-01-03T03:04:05Z")

	adv := &repository.Advisory{
		GhsaID:      "GHSA-abc",
		Summary:     "Test advisory",
		Description: utils.Ref("Desc"),
		Severity:    utils.Ref("HIGH"),
		Publisher:   &repository.User{Login: "user", HTMLURL: "https://github.com/user"},
		Identifiers: []repository.Identifier{{Value: "GHSA-abc"}},
		PublishedAt: &pubDate,
		UpdatedAt:   &updDate,
		Vulnerabilities: []repository.Vulnerability{{
			Package:                &repository.Package{Ecosystem: "Go", Name: utils.Ref("github.com/acme/lib/v2")},
			VulnerableVersionRange: utils.Ref("<=1.2.3"),
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

func Test_ToCSAF_Global_Example(t *testing.T) {
	// Load global GHSA example
	data, err := os.ReadFile("../../examples/global_GHSA/GHSA-cpj6-fhp6-mr6j.json")
	if err != nil {
		t.Fatalf("failed to read example file: %v", err)
	}

	var g global.Advisory
	if err := json.Unmarshal(data, &g); err != nil {
		t.Fatalf("failed to unmarshal global advisory: %v", err)
	}

	csafAdv, err := ToCSAF(&g)
	if err != nil {
		t.Fatalf("ToCSAF returned error: %v", err)
	}

	if csafAdv.Document == nil {
		t.Fatal("csafAdv.Document is nil")
	}
	if *csafAdv.Document.Tracking.ID != "GHSA-cpj6-fhp6-mr6j" {
		t.Errorf("got tracking ID %v, want GHSA-cpj6-fhp6-mr6j", *csafAdv.Document.Tracking.ID)
	}
	if *csafAdv.Document.Publisher.Name != "github" {
		t.Errorf("got publisher %v, want github", *csafAdv.Document.Publisher.Name)
	}

	if len(csafAdv.Vulnerabilities) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(csafAdv.Vulnerabilities))
	}
	v := csafAdv.Vulnerabilities[0]
	if *v.CVE != "CVE-2025-43865" {
		t.Errorf("got CVE %v, want CVE-2025-43865", *v.CVE)
	}
}
