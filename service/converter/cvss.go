package converter

import (
	"fmt"
	"strings"

	gocvss30 "github.com/pandatix/go-cvss/30"
	gocvss31 "github.com/pandatix/go-cvss/31"
)

// cvss3BaseScore computes the base score of a CVSS v3.0/v3.1 vector string. We compute it
// ourselves instead of trusting the score shipped in the GHSA, so that the CSAF score is
// always consistent with its vector.
func cvss3BaseScore(vector string) (float64, error) {
	switch {
	case strings.HasPrefix(vector, "CVSS:3.1/"):
		c, err := gocvss31.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("invalid CVSS v3.1 vector %s: %w", vector, err)
		}
		return c.BaseScore(), nil
	case strings.HasPrefix(vector, "CVSS:3.0/"):
		c, err := gocvss30.ParseVector(vector)
		if err != nil {
			return 0, fmt.Errorf("invalid CVSS v3.0 vector %s: %w", vector, err)
		}
		return c.BaseScore(), nil
	default:
		return 0, fmt.Errorf("not a CVSS v3 vector: %s", vector)
	}
}
