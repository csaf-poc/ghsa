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

func printUsage() {
	fmt.Fprintf(os.Stderr, "ghsaToCSAF - A tool to convert GitHub Security Advisories to CSAF\n\n")
	fmt.Fprintf(os.Stderr, "Usage:\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF [subcommand] [args] [flags]\n\n")
	fmt.Fprintf(os.Stderr, "Subcommands:\n")
	fmt.Fprintf(os.Stderr, "  global <ID|URL>             Fetch a global advisory from the GitHub Advisory Database\n")
	fmt.Fprintf(os.Stderr, "  repository <repo> <ID|URL>  Fetch a security advisory from a specific repository\n")
	fmt.Fprintf(os.Stderr, "  allOfRepository <repo>      Fetch all published security advisories from a repository\n")
	fmt.Fprintf(os.Stderr, "  auto <input>                Auto-detect input type (default behavior)\n\n")
	fmt.Fprintf(os.Stderr, "Aliases:\n")
	fmt.Fprintf(os.Stderr, "  repo -> repository\n")
	fmt.Fprintf(os.Stderr, "  all  -> allOfRepository\n\n")
	fmt.Fprintf(os.Stderr, "Flags:\n")
	fmt.Fprintf(os.Stderr, "  -o <path>                   Output file or directory (default: <ID>.json or advisories/)\n")
	fmt.Fprintf(os.Stderr, "  -h, --help                  Show this help message\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF global GHSA-cpj6-fhp6-mr6j\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF repo golang-jwt/jwt GHSA-mh63-6h87-95cp\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF all golang-jwt/jwt -o ./jwt-advisories\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF https://github.com/advisories/GHSA-cpj6-fhp6-mr6j\n")
}

func main() {
	// Root flags
	outputFlag := flag.String("o", "", "Output destination")
	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() == 0 {
		printUsage()
		os.Exit(1)
	}

	command := flag.Arg(0)
	remainingArgs := flag.Args()[1:]

	var advisories []ghsa.GHSAAdvisory
	var err error
	output := *outputFlag

	switch strings.ToLower(command) {
	case "global":
		advisories, output, err = handleGlobal(remainingArgs, output)
	case "repository", "repo":
		advisories, output, err = handleRepository(remainingArgs, output)
	case "allofrepository", "all", "list":
		advisories, output, err = handleAll(remainingArgs, output)
	case "auto":
		advisories, output, err = handleAuto(remainingArgs, output)
	case "help":
		printUsage()
		os.Exit(0)
	default:
		// Try auto-detection for anything else (legacy/direct mode)
		advisories, output, err = handleAuto(flag.Args(), output)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	if len(advisories) == 0 {
		slog.Warn("No advisories found")
		return
	}

	// Apply default output naming if none provided
	if output == "" {
		if len(advisories) == 1 {
			output = strings.ToLower(advisories[0].GetGhsaID()) + ".json"
		} else {
			output = "advisories"
		}
		slog.Info("No output specified, using default", slog.String("output", output))
	}

	runConversion(advisories, output)
}

func handleGlobal(args []string, output string) ([]ghsa.GHSAAdvisory, string, error) {
	fs := flag.NewFlagSet("global", flag.ContinueOnError)
	o := fs.String("o", output, "Output destination")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return nil, "", fmt.Errorf("global command requires an ID or URL")
	}
	input := fs.Arg(0)
	advs, err := downloader.FetchAdvisories(input)
	return advs, *o, err
}

func handleRepository(args []string, output string) ([]ghsa.GHSAAdvisory, string, error) {
	fs := flag.NewFlagSet("repository", flag.ContinueOnError)
	o := fs.String("o", output, "Output destination")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return nil, "", fmt.Errorf("repository command requires at least <owner/repo>")
	}

	repo := fs.Arg(0)
	input := repo
	if fs.NArg() >= 2 {
		id := fs.Arg(1)
		if !strings.Contains(id, "://") && !strings.Contains(id, "/") {
			// Construct URL from repo and ID
			input = fmt.Sprintf("https://github.com/%s/security/advisories/%s", repo, id)
		} else {
			input = id
		}
	}

	advs, err := downloader.FetchAdvisories(input)
	return advs, *o, err
}

func handleAll(args []string, output string) ([]ghsa.GHSAAdvisory, string, error) {
	fs := flag.NewFlagSet("allOfRepository", flag.ContinueOnError)
	o := fs.String("o", output, "Output destination")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return nil, "", fmt.Errorf("allOfRepository command requires <owner/repo>")
	}
	input := fs.Arg(0)
	advs, err := downloader.FetchAdvisories(input)
	return advs, *o, err
}

func handleAuto(args []string, output string) ([]ghsa.GHSAAdvisory, string, error) {
	fs := flag.NewFlagSet("auto", flag.ContinueOnError)
	o := fs.String("o", output, "Output destination")
	fs.Parse(args)

	if fs.NArg() < 1 {
		return nil, "", fmt.Errorf("no input provided")
	}

	// In auto mode, we might have ghsa <input> <output> for legacy support
	input := fs.Arg(0)
	if *o == "" && fs.NArg() >= 2 {
		*o = fs.Arg(1)
	}

	advs, err := downloader.FetchAdvisories(input)
	return advs, *o, err
}

func runConversion(advisories []ghsa.GHSAAdvisory, output string) {
	outputBase := output
	isDir := false
	if info, err := os.Stat(outputBase); err == nil && info.IsDir() {
		isDir = true
	}

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
			filename = filepath.Join(outputBase, strings.ToLower(adv.GetGhsaID())+".json")
		} else if len(advisories) > 1 {
			// Batch into a new directory if it doesn't exist
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
