package main

import (
	"fmt"
	"os"

	"github.com/csaf-poc/ghsa/internal"
	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

// TODO(lebogg): Implement entrypoint: URL of GHSA as argument |
func main() {
	var (
		ghsa  *repository.Advisory
		csafa *csaf.Advisory
		err   error
	)

	// Check arguments
	if len(os.Args) != 2 {
		fmt.Printf("Usage: %s <GHSA URL>\n", os.Args[0])
		os.Exit(1)
	}

	// Get GHSA
	ghsaURL := os.Args[1]
	ghsa, err = internal.DownloadGHSA(ghsaURL)
	if err != nil {
		fmt.Printf("Error downloading GHSA: %v\n", err)
		os.Exit(1)
	}

	// Convert GHSA to CSAF
	csafa, err = internal.ToCSAF(ghsa)
	if err != nil {
		fmt.Printf("Error converting GHSA to CSAF: %v\n", err)
		os.Exit(1)
	}

	// Store CSAF
	err = internal.StoreCSAF(csafa)
	if err != nil {
		fmt.Printf("Error storing CSAF: %v\n", err)
		os.Exit(1)
	}
}
