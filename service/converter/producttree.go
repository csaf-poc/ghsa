package converter

import (
	"fmt"
	"strings"

	"github.com/csaf-poc/ghsa/internal/utils"
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"

	gocsaf "github.com/gocsaf/csaf/v3/csaf"
)

// TODO(lebogg): Implement
// getProductTree converts GHSA vulnerability information into a CSAF product tree.
// It builds a hierarchical structure: vendor -> product_name -> product_version_range
// for each vulnerable package and version range in the advisory.
func getProductTree(adv *repository.Advisory) (pt *csaf.ProductTree, err error) {
	// In a GHSA, vulnerabilities represent affected packages along with their versions
	if len(adv.Vulnerabilities) == 0 {
		return nil, fmt.Errorf("no affected packages found in advisory")
	}
	var branches gocsaf.Branches
	for _, v := range adv.Vulnerabilities {
		branch := &gocsaf.Branch{
			// 1st) add ecosystem branch, 2nd) add product branch and 3rd) add version range
			// Note: CSAF only allows a branch to EITHER have a branch OR a product
			// TODO(lebogg): What is the right category here? Language is probably no programming language but would be fit here. Vendor would be, e.g., GitHub or the Package Owner.
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
									Name:     utils.Ref(v.VulnerableVersionRange),
									Product: &gocsaf.FullProductName{
										Name:      getRepositoryName(v.Package.Name),
										ProductID: utils.Ref(gocsaf.ProductID(v.Package.Name)),
									},
								},
							},
						},
					},
				},
			},
		}
		branches = append(pt.Branches, branch)
	}
	pt = &gocsaf.ProductTree{Branches: branches}
	return
}

// getRepositoryName gets the repository name out of the package name.
// For example: "github.com/golang-jwt/jwt/v5" -> "jwt"
// TODO(lebogg): Check if there are other GitHub URL constellations
func getRepositoryName(packageName string) *string {
	splits := strings.Split(packageName, "/")
	if len(splits) > 2 {
		return utils.Ref(splits[2])
	} else {
		// If split is too small, we just return the whole package name.
		return utils.Ref(packageName)
	}
}
