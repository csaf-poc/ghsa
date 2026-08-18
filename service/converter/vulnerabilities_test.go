package converter

import (
	"testing"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

func Test_getCWE_and_getCVE(t *testing.T) {
	adv := &repository.Advisory{
		CveID: utils.Ref("CVE-2024-0001"),
		CWEs:  []repository.CWE{{CWEID: "CWE-79", Name: "XSS"}},
	}
	cve := getCVE(adv)
	if cve == nil || *cve != gocsaf.CVE("CVE-2024-0001") {
		t.Errorf("cve = %v, want CVE-2024-0001", cve)
	}
	cwe := getCWE(adv)
	if cwe == nil {
		t.Fatalf("cwe = nil, want CWE-79")
	}
	if cwe.ID == nil || *cwe.ID != gocsaf.WeaknessID("CWE-79") {
		t.Errorf("cwe.ID = %v, want CWE-79", cwe.ID)
	}
	if cwe.Name == nil || *cwe.Name != "XSS" {
		t.Errorf("cwe.Name = %v, want XSS", cwe.Name)
	}
}

func Test_getReferences(t *testing.T) {
	adv := &repository.Advisory{HTMLURL: "https://github.com/org/repo/security/advisories/GHSA-xxx"}
	r := getReferences(adv)
	if len(r) != 1 || r[0].URL == nil || *r[0].URL != adv.HTMLURL {
		t.Errorf("reference URL = %v, want %v", r[0].URL, adv.HTMLURL)
	}
}

func Test_convertScores_PrefersCVSSv3WhenV3AndV4Exist(t *testing.T) {
	adv := &repository.Advisory{
		CVSSSeverities: repository.CVSSSeverities{
			CVSSv3: repository.CVSS{VectorString: utils.Ref("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L"), Score: utils.Ref(7.3)},
			CVSSv4: repository.CVSS{VectorString: utils.Ref("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), Score: utils.Ref(9.9)},
		},
	}
	pid := gocsaf.ProductID("pkg-1")
	products := gocsaf.Products{&pid}

	score, err := convertScores(adv, products)
	if err != nil {
		t.Fatalf("convertScores returned error: %v", err)
	}
	if score == nil || score.CVSS3 == nil || score.CVSS3.BaseScore == nil {
		t.Fatalf("expected CVSS3 score, got %#v", score)
	}
	if *score.CVSS3.BaseScore != 7.3 {
		t.Fatalf("expected v3 score 7.3, got %v", *score.CVSS3.BaseScore)
	}
}

func Test_getVulnerabilities_AddsNoteWhenOnlyMeaningfulV4Exists(t *testing.T) {
	adv := &repository.Advisory{
		GhsaID: "GHSA-v4-only",
		CVSSSeverities: repository.CVSSSeverities{
			CVSSv4: repository.CVSS{VectorString: utils.Ref("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"), Score: utils.Ref(8.8)},
		},
		Vulnerabilities: []repository.Vulnerability{{
			Package:                &repository.Package{Ecosystem: "go", Name: utils.Ref("github.com/acme/lib/v2")},
			VulnerableVersionRange: utils.Ref("<=1.2.3"),
		}},
	}

	pt, err := getProductTree(adv)
	if err != nil {
		t.Fatalf("getProductTree returned error: %v", err)
	}
	vulns, err := getVulnerabilities(adv, pt)
	if err != nil {
		t.Fatalf("getVulnerabilities returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if len(vulns[0].Scores) != 0 {
		t.Fatalf("expected no scores for v4-only advisory, got %d", len(vulns[0].Scores))
	}
	if len(vulns[0].Notes) != 1 {
		t.Fatalf("expected 1 conversion note, got %d", len(vulns[0].Notes))
	}
}

func Test_getVulnerabilities_V4ZeroAndNoVectorTreatedAsAbsentScore(t *testing.T) {
	adv := &repository.Advisory{
		GhsaID: "GHSA-v4-empty",
		CVSSSeverities: repository.CVSSSeverities{
			CVSSv4: repository.CVSS{VectorString: utils.Ref(""), Score: utils.Ref(float64(0))},
		},
		Vulnerabilities: []repository.Vulnerability{{
			Package:                &repository.Package{Ecosystem: "go", Name: utils.Ref("github.com/acme/lib/v2")},
			VulnerableVersionRange: utils.Ref("<=1.2.3"),
		}},
	}

	pt, err := getProductTree(adv)
	if err != nil {
		t.Fatalf("getProductTree returned error: %v", err)
	}
	vulns, err := getVulnerabilities(adv, pt)
	if err != nil {
		t.Fatalf("getVulnerabilities returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if len(vulns[0].Scores) != 0 {
		t.Fatalf("expected no scores for empty v4 advisory, got %d", len(vulns[0].Scores))
	}
	if len(vulns[0].Notes) != 0 {
		t.Fatalf("expected no conversion note for empty v4 advisory, got %d", len(vulns[0].Notes))
	}
}

func Test_getVulnerabilities_KeepsRemediationsPerProduct(t *testing.T) {
	adv := &repository.Advisory{
		GhsaID: "GHSA-remediation-test",
		Vulnerabilities: []repository.Vulnerability{
			{
				Package:                &repository.Package{Ecosystem: "go", Name: utils.Ref("github.com/golang-jwt/jwt/v5")},
				VulnerableVersionRange: utils.Ref("<= 5.2.1"),
				PatchedVersions:        utils.Ref("5.2.2"),
			},
			{
				Package:                &repository.Package{Ecosystem: "go", Name: utils.Ref("github.com/golang-jwt/jwt/v4")},
				VulnerableVersionRange: utils.Ref("<= 4.5.1"),
				PatchedVersions:        utils.Ref("4.5.2"),
			},
		},
	}

	pt, err := getProductTree(adv)
	if err != nil {
		t.Fatalf("getProductTree returned error: %v", err)
	}
	vulns, err := getVulnerabilities(adv, pt)
	if err != nil {
		t.Fatalf("getVulnerabilities returned error: %v", err)
	}
	if len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability, got %d", len(vulns))
	}
	if len(vulns[0].Remediations) != 2 {
		t.Fatalf("expected 2 remediations, got %d", len(vulns[0].Remediations))
	}

	first := vulns[0].Remediations[0]
	if first.Details == nil || *first.Details != "Upgrade to version: 5.2.2" {
		t.Fatalf("first remediation details = %v, want Upgrade to version: 5.2.2", first.Details)
	}
	if first.ProductIds == nil || len(*first.ProductIds) != 1 || (*first.ProductIds)[0] == nil || *(*first.ProductIds)[0] != "github.com/golang-jwt/jwt/v5:lte-5.2.1" {
		t.Fatalf("first remediation product IDs = %v, want github.com/golang-jwt/jwt/v5:lte-5.2.1", first.ProductIds)
	}

	second := vulns[0].Remediations[1]
	if second.Details == nil || *second.Details != "Upgrade to version: 4.5.2" {
		t.Fatalf("second remediation details = %v, want Upgrade to version: 4.5.2", second.Details)
	}
	if second.ProductIds == nil || len(*second.ProductIds) != 1 || (*second.ProductIds)[0] == nil || *(*second.ProductIds)[0] != "github.com/golang-jwt/jwt/v4:lte-4.5.1" {
		t.Fatalf("second remediation product IDs = %v, want github.com/golang-jwt/jwt/v4:lte-4.5.1", second.ProductIds)
	}
}
