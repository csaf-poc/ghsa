package main

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/csaf-poc/ghsa/models/csaf"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
	"github.com/csaf-poc/ghsa/service/converter"
	"github.com/csaf-poc/ghsa/service/downloader"
	"github.com/csaf-poc/ghsa/service/store"
)

// TODO(lebogg): Implement entrypoint: URL of GHSA as argument |
func main() {
	var (
		ghsa  *repository.Advisory
		csafa *csaf.Advisory
		err   error
	)
	checkInput()

	// Get GHSA
	ghsaURL := os.Args[1]
	ghsa, err = downloader.DownloadGHSA(ghsaURL)
	if err != nil {
		fmt.Printf("Error downloading GHSA: %v\n", err)
		os.Exit(1)
	}

	// Convert GHSA to CSAF
	csafa, err = converter.ToCSAF(ghsa)
	if err != nil {
		fmt.Printf("Error converting GHSA to CSAF: %v\n", err)
		os.Exit(1)
	}

	// Store CSAF
	err = store.Save(csafa, os.Args[2])
	if err != nil {
		fmt.Printf("Error saving CSAF: %v\n", err)
		os.Exit(1)
	}
}

// TODO(lebogg): fmt sometimes slower then following slog?
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
