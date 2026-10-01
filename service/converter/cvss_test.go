package converter

import (
	"testing"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

func Test_cvss3BaseScore(t *testing.T) {
	tests := []struct {
		vector string
		want   float64
	}{
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H", 7.5},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H", 10.0},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L", 7.3},
		{"CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N", 5.4},
		{"CVSS:3.1/AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:N/A:N", 1.8},
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:N", 0.0},
		{"CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N", 6.1},
		// Temporal/environmental metrics are ignored for the base score.
		{"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H/E:U/RL:O", 9.8},
	}
	for _, tt := range tests {
		got, err := cvss3BaseScore(tt.vector)
		if err != nil {
			t.Errorf("cvss3BaseScore(%s) returned error: %v", tt.vector, err)
			continue
		}
		if got != tt.want {
			t.Errorf("cvss3BaseScore(%s) = %v, want %v", tt.vector, got, tt.want)
		}
	}
}

func Test_cvss3BaseScore_Invalid(t *testing.T) {
	for _, vector := range []string{
		"CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H",     // missing A
		"CVSS:3.1/AV:X/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", // invalid AV
		"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
	} {
		if _, err := cvss3BaseScore(vector); err == nil {
			t.Errorf("cvss3BaseScore(%s) expected error", vector)
		}
	}
}

func Test_convertScores_UsesComputedScore(t *testing.T) {
	adv := &repository.Advisory{
		CVSSSeverities: repository.CVSSSeverities{
			// GHSA ships no score for this vector; previously this produced baseScore 0.0 / NONE.
			CVSSv3: repository.CVSS{VectorString: utils.Ref("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H")},
		},
	}
	pid := gocsaf.ProductID("pkg-1")

	score, err := convertScores(adv, gocsaf.Products{&pid})
	if err != nil {
		t.Fatalf("convertScores returned error: %v", err)
	}
	if *score.CVSS3.BaseScore != 7.5 || *score.CVSS3.BaseSeverity != gocsaf.CVSS3SeverityHigh {
		t.Errorf("got %v/%v, want 7.5/HIGH", *score.CVSS3.BaseScore, *score.CVSS3.BaseSeverity)
	}
}
