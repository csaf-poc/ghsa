package converter

import (
	"fmt"
	"math"
	"strings"
)

// cvss3BaseScore computes the base score of a CVSS v3.0/v3.1 vector string as defined
// in the specification (section 7.1 for v3.1). We compute it ourselves instead of
// trusting the score shipped in the GHSA, so that the CSAF score is always consistent
// with its vector.
func cvss3BaseScore(vector string) (float64, error) {
	parts := strings.Split(vector, "/")
	if len(parts) < 9 {
		return 0, fmt.Errorf("incomplete CVSS v3 vector: %s", vector)
	}

	version := parts[0]
	if version != "CVSS:3.0" && version != "CVSS:3.1" {
		return 0, fmt.Errorf("not a CVSS v3 vector: %s", vector)
	}

	metrics := make(map[string]string, len(parts)-1)
	for _, p := range parts[1:] {
		k, v, ok := strings.Cut(p, ":")
		if !ok {
			return 0, fmt.Errorf("malformed CVSS metric %q in %s", p, vector)
		}
		metrics[k] = v
	}

	scopeChanged := metrics["S"] == "C"
	if s := metrics["S"]; s != "U" && s != "C" {
		return 0, fmt.Errorf("invalid or missing scope in %s", vector)
	}

	weights := map[string]map[string]float64{
		"AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
		"AC": {"L": 0.77, "H": 0.44},
		"UI": {"N": 0.85, "R": 0.62},
		"C":  {"H": 0.56, "L": 0.22, "N": 0},
		"I":  {"H": 0.56, "L": 0.22, "N": 0},
		"A":  {"H": 0.56, "L": 0.22, "N": 0},
	}
	if scopeChanged {
		weights["PR"] = map[string]float64{"N": 0.85, "L": 0.68, "H": 0.5}
	} else {
		weights["PR"] = map[string]float64{"N": 0.85, "L": 0.62, "H": 0.27}
	}

	w := make(map[string]float64, len(weights))
	for metric, values := range weights {
		v, ok := values[metrics[metric]]
		if !ok {
			return 0, fmt.Errorf("invalid or missing metric %s in %s", metric, vector)
		}
		w[metric] = v
	}

	iss := 1 - (1-w["C"])*(1-w["I"])*(1-w["A"])
	var impact float64
	if scopeChanged {
		impact = 7.52*(iss-0.029) - 3.25*math.Pow(iss-0.02, 15)
	} else {
		impact = 6.42 * iss
	}
	exploitability := 8.22 * w["AV"] * w["AC"] * w["PR"] * w["UI"]

	if impact <= 0 {
		return 0, nil
	}

	roundup := roundup31
	if version == "CVSS:3.0" {
		roundup = roundup30
	}
	if scopeChanged {
		return roundup(math.Min(1.08*(impact+exploitability), 10)), nil
	}
	return roundup(math.Min(impact+exploitability, 10)), nil
}

// roundup30 is the Roundup function of CVSS v3.0.
func roundup30(x float64) float64 {
	return math.Ceil(x*10) / 10
}

// roundup31 is the Roundup function of CVSS v3.1 (Appendix A), which avoids
// floating point artifacts such as 4.000000001 being rounded up to 4.1.
func roundup31(x float64) float64 {
	i := int64(math.Round(x * 100000))
	if i%10000 == 0 {
		return float64(i) / 100000
	}
	return (math.Floor(float64(i)/10000) + 1) / 10
}
