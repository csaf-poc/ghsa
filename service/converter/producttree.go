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
		productName := &gocsaf.FullProductName{
			Name:      getRepositoryName(v.Package.Name),
			ProductID: utils.Ref(gocsaf.ProductID(v.Package.Name)),
		}
		branch := &gocsaf.Branch{
			// 1st) add ecosystem branch, 2nd) add product branch and 3rd) add version range
			// Note: CSAF only allows a branch to EITHER have a branch OR a product
			// Assumption: Language also comprises programming languages
			Category: utils.Ref(gocsaf.CSAFBranchCategoryLanguage),
			Name:     utils.Ref(v.Package.Ecosystem),
			Branches: []*gocsaf.Branch{
				{
					Branches: []*gocsaf.Branch{
						{
							Category: utils.Ref(gocsaf.CSAFBranchCategoryProductName),
							Name:     utils.Ref(v.Package.Name),
							Branches: []*gocsaf.Branch{
								{
									Category: utils.Ref(gocsaf.CSAFBranchCategoryProductVersionRange),
									Name:     utils.Ref(normalizeOperators(v.VulnerableVersionRange)),
									Product:  productName,
								},
							},
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

// getRepositoryName extracts repository name heuristically from package path.
// For example: "github.com/golang-jwt/jwt/v5" -> "jwt"
func getRepositoryName(packageName string) *string {
	splits := strings.Split(packageName, "/")
	if len(splits) > 2 {
		return utils.Ref(splits[2])
	} else {
		// If split is too small, we just return the whole package name.
		return utils.Ref(packageName)
	}
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
