package converter

import (
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
	"testing"
)

func Test_getCWE_and_getCVE(t *testing.T) {
	adv := &repository.Advisory{
		CveID: "CVE-2024-0001",
		CWEs:  []repository.CWE{{CWEID: "CWE-79", Name: "XSS"}},
	}
	cve := getCVE(adv)
	if cve == nil || *cve != gocsaf.CVE("CVE-2024-0001") {
		t.Errorf("cve = %v, want CVE-2024-0001", cve)
	}
	cwe := getCWE(adv)
	if cwe == nil || cwe.ID == nil || *cwe.ID != gocsaf.WeaknessID("CWE-79") {
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
