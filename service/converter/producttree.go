package converter

import (
	"fmt"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

// getProductTree builds a CSAF product tree from GHSA vulnerabilities.
// It converts GHSA vulnerability information into a CSAF product tree.
// It builds a hierarchical structure: vendor -> product_name -> product_version_range
// for each vulnerable package and version range in the advisory.
func getProductTree(adv *repository.Advisory) (pt *csaf.ProductTree, err error) {
	// In a GHSA, vulnerabilities represent affected packages along with their versions
	if len(adv.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("no affected packages found in advisory")
	}
	var (
		branches     gocsaf.Branches
		productNames gocsaf.FullProductNames
	)

	for _, v := range adv.Vulnerabilities {
		// Include the version range in product_id so entries for the same package with
		// different ranges stay distinct (product_id must be unique within the document).
		productID := gocsaf.ProductID(v.Package.Name + ":" + v.VulnerableVersionRange)
		productName := &gocsaf.FullProductName{
			Name:      getRepositoryName(v.Package.Name),
			ProductID: utils.Ref(productID),
		}
		branch := &gocsaf.Branch{
			// 1st) add ecosystem branch, 2nd) add product branch and 3rd) add version range
			// Note: CSAF only allows a branch to EITHER have a branch OR a product
			// Assumption: Language also comprises programming languages
			// The schema requires every branch to have a non-empty category (from the enum)
			// and a non-empty name — so we never emit an intermediate "unnamed" branch like vendor.
			Category: utils.Ref(gocsaf.CSAFBranchCategoryLanguage),
			Name:     utils.Ref(v.Package.Ecosystem),
			Branches: []*gocsaf.Branch{
				{
					Category: utils.Ref(gocsaf.CSAFBranchCategoryProductName),
					Name:     utils.Ref(v.Package.Name),
					Branches: []*gocsaf.Branch{
						{
							// CSAF 2.0 does not define `product_version_range`; that category was
							// added in CSAF 2.1. We use `product_version` and keep the range
							// expression in `name` as a workaround.
							Category: utils.Ref(gocsaf.CSAFBranchCategoryProductVersion),
							Name:     utils.Ref(normalizeOperators(v.VulnerableVersionRange)),
							Product:  productName,
						},
					},
				},
			},
		}
		branches = append(branches, branch)
		productNames = append(productNames, productName)
	}
	pt = &gocsaf.ProductTree{
		Branches:         branches,
		FullProductNames: utils.Ref(productNames),
	}
	return
}

// flatVCSHostPrefixes lists VCS hosts whose repo URLs use a flat
// <host>/<owner>/<repo>[/...] layout — i.e. the repo segment is always at
// index 2. GitLab is deliberately excluded because it supports nested
// subgroups (gitlab.com/group/subgroup/.../repo), so the repo boundary
// cannot be inferred from the path alone.
var flatVCSHostPrefixes = []string{
	"github.com/",
	"bitbucket.org/",
}

// getRepositoryName returns a short, human-readable product name for a GHSA
// package. For Go module paths hosted on a flat-namespace VCS provider it
// extracts the repo segment (e.g. "github.com/golang-jwt/jwt/v5" -> "jwt").
// For all other package names — GitLab paths (subgroup depth is unknown),
// Go vanity imports, and flat ecosystem identifiers (npm, PyPI, Maven,
// Composer, ...) — the full name is returned unchanged.
func getRepositoryName(packageName string) *string {
	for _, prefix := range flatVCSHostPrefixes {
		if strings.HasPrefix(packageName, prefix) {
			splits := strings.Split(packageName, "/")
			if len(splits) > 2 {
				return utils.Ref(splits[2])
			}
			break
		}
	}
	return utils.Ref(packageName)
}

// normalizeOperators expands comparison operators to English phrases and normalizes spacing.
// It replaces ASCII operators to avoid '<'/'>' HTML escapes, like "\u003".
// Note: We cannot touch the encoding of [gocsaf.SaveAdvisory]
func normalizeOperators(r string) string {
	// Replace operators with phrases
	r = strings.ReplaceAll(r, "<=", " less or equal ")
	r = strings.ReplaceAll(r, ">=", " greater or equal ")
	r = strings.ReplaceAll(r, "<", " less than ")
	r = strings.ReplaceAll(r, ">", " greater than ")

	r = strings.TrimSpace(r)
	return r
}
