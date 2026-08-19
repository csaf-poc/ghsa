package main

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/csaf-poc/ghsa/models/ghsa"
	"github.com/csaf-poc/ghsa/service/converter"
	"github.com/csaf-poc/ghsa/service/downloader"
	"github.com/csaf-poc/ghsa/service/store"
)

func main() {
	var (
		advisories []ghsa.GHSAAdvisory
		err        error
	)
	checkInput()

	// Get GHSA(s)
	ghsaURL := os.Args[1]
	advisories, err = downloader.FetchAdvisories(ghsaURL)
	if err != nil {
		fmt.Printf("Error fetching advisories: %v\n", err)
		os.Exit(1)
	}

	outputBase := os.Args[2]
	isDir := false
	if info, err := os.Stat(outputBase); err == nil && info.IsDir() {
		isDir = true
	}

	for _, adv := range advisories {
		// Convert GHSA to CSAF
		csafa, err := converter.ToCSAF(adv)
		if err != nil {
			fmt.Printf("Error converting GHSA %s to CSAF: %v\n", adv.GetGhsaID(), err)
			continue
		}

		// Determine filename
		var filename string
		if isDir {
			filename = fmt.Sprintf("%s/%s.json", strings.TrimSuffix(outputBase, "/"), adv.GetGhsaID())
		} else if len(advisories) > 1 {
			// If multiple advisories but outputBase is not a directory, we use it as a prefix or fail?
			// Let's use it as a directory if it doesn't exist yet and we have multiple advisories.
			if _, err := os.Stat(outputBase); os.IsNotExist(err) {
				if err := os.MkdirAll(outputBase, 0755); err == nil {
					isDir = true
					filename = fmt.Sprintf("%s/%s.json", strings.TrimSuffix(outputBase, "/"), adv.GetGhsaID())
				} else {
					filename = fmt.Sprintf("%s-%s.json", outputBase, adv.GetGhsaID())
				}
			} else {
				filename = fmt.Sprintf("%s-%s.json", outputBase, adv.GetGhsaID())
			}
		} else {
			filename = outputBase
		}

		// Store CSAF
		err = store.Save(csafa, filename)
		if err != nil {
			fmt.Printf("Error saving CSAF for %s: %v\n", adv.GetGhsaID(), err)
		}
	}
}

// checkInput validates CLI arguments and prints usage on mismatch.
func checkInput() {
	if length := len(os.Args); length != 3 {
		fmt.Printf("Usage: %s <GHSA_URL> <file_name>\n", os.Args[0])
		switch length {
		case 1:
			slog.Info("Provided no arguments at all")
		case 2:
			slog.Info("Provided arguments", slog.Any("<GHSA_URL>", os.Args[1]))
		default:
			slog.Info("Provided too many arguments", slog.Any("Argument number", length-1))
		}
		os.Exit(1)
	}
}
