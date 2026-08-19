package main

import (
	"flag"
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
		output     string
	)

	// Define flags
	globalFlag := flag.String("global", "", "Fetch a global GHSA by ID (e.g., GHSA-cpj6-fhp6-mr6j)")
	repoFlag := flag.String("repo", "", "Repository owner/name (e.g., golang-jwt/jwt)")
	advisoryFlag := flag.String("advisory", "", "Specific GHSA ID to fetch from a repository (use with -repo)")
	allFromRepoFlag := flag.String("allFromRepo", "", "Fetch all GHSA from a repository owner/name (e.g., golang-jwt/jwt)")
	outputFlag := flag.String("o", "", "Output file or directory")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage of %s:\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Legacy style:   %s <GHSA_URL_OR_REPO> <OUTPUT_PATH>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Flag style:     %s [-o OUTPUT] [-global ID | -allFromRepo OWNER/REPO | -repo OWNER/REPO -advisory ID]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	// Determine input and output
	if *globalFlag != "" || *repoFlag != "" || *allFromRepoFlag != "" {
		// Flag-based mode
		output = *outputFlag
		if *globalFlag != "" {
			url := fmt.Sprintf("https://github.com/advisories/%s", *globalFlag)
			advisories, err = downloader.FetchAdvisories(url)
		} else if *allFromRepoFlag != "" {
			advisories, err = downloader.FetchAdvisories(*allFromRepoFlag)
		} else if *repoFlag != "" {
			if *advisoryFlag == "" {
				fmt.Println("Error: -advisory ID must be specified when using -repo")
				flag.Usage()
				os.Exit(1)
			}
			url := fmt.Sprintf("https://github.com/advisories/%s/%s/security/advisories/%s", strings.Split(*repoFlag, "/")[0], strings.Split(*repoFlag, "/")[1], *advisoryFlag)
			// Actually, normalizeGHSAURL handles https://github.com/OWNER/REPO/security/advisories/ID
			url = fmt.Sprintf("https://github.com/%s/security/advisories/%s", *repoFlag, *advisoryFlag)
			advisories, err = downloader.FetchAdvisories(url)
		}
	} else if flag.NArg() == 1 || flag.NArg() == 2 {
		// Legacy positional mode
		input := flag.Arg(0)
		if flag.NArg() == 2 {
			output = flag.Arg(1)
		}
		advisories, err = downloader.FetchAdvisories(input)
	} else {
		flag.Usage()
		os.Exit(1)
	}

	if err != nil {
		fmt.Printf("Error fetching advisories: %v\n", err)
		os.Exit(1)
	}

	if len(advisories) > 0 && output == "" {
		if len(advisories) == 1 {
			output = strings.ToLower(advisories[0].GetGhsaID()) + ".json"
		} else {
			output = "advisories" // default directory name for multiple
		}
		slog.Info("No output specified, using default", slog.String("output", output))
	}

	outputBase := output
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
