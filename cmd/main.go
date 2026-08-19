package main

import (
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
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

	// Determine output mode and process advisories
	successCount := 0
	for _, adv := range advisories {
		// Convert GHSA to CSAF
		csafa, err := converter.ToCSAF(adv)
		if err != nil {
			slog.Error("Error converting GHSA to CSAF",
				slog.String("GHSA ID", adv.GetGhsaID()),
				slog.Any("error", err))
			continue
		}

		// Determine filename
		var filename string
		if isDir {
			// Systematic directory output
			filename = filepath.Join(outputBase, strings.ToLower(adv.GetGhsaID())+".json")
		} else if len(advisories) > 1 {
			// Batch into a new directory if it doesn't exist, otherwise use prefix
			if _, err := os.Stat(outputBase); os.IsNotExist(err) {
				if err := os.MkdirAll(outputBase, 0755); err == nil {
					isDir = true
					filename = filepath.Join(outputBase, strings.ToLower(adv.GetGhsaID())+".json")
				} else {
					filename = fmt.Sprintf("%s-%s.json", outputBase, strings.ToLower(adv.GetGhsaID()))
				}
			} else {
				filename = fmt.Sprintf("%s-%s.json", outputBase, strings.ToLower(adv.GetGhsaID()))
			}
		} else {
			// Single file output
			filename = outputBase
		}

		// Store CSAF
		err = store.Save(csafa, filename)
		if err != nil {
			slog.Error("Error saving CSAF",
				slog.String("GHSA ID", adv.GetGhsaID()),
				slog.String("filename", filename),
				slog.Any("error", err))
			continue
		}
		successCount++
	}

	if len(advisories) > 0 && successCount == 0 {
		slog.Error("Failed to process any advisories")
		os.Exit(1)
	}

	slog.Info("Processing complete",
		slog.Int("total", len(advisories)),
		slog.Int("successful", successCount))
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
