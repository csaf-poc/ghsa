package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"

	"github.com/csaf-poc/ghsa/internal/config"
	"github.com/csaf-poc/ghsa/models/ghsa"
	"github.com/csaf-poc/ghsa/service/converter"
	"github.com/csaf-poc/ghsa/service/downloader"
	"github.com/csaf-poc/ghsa/service/store"
)

// printUsage prints the help message for the CLI.
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
	fmt.Fprintf(os.Stderr, "  --config <file>             JSON config, e.g. {\"publisher\": {\"category\": \"vendor\", \"name\": ...}}\n")
	fmt.Fprintf(os.Stderr, "  -h, --help                  Show this help message\n\n")
	fmt.Fprintf(os.Stderr, "Examples:\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF global GHSA-cpj6-fhp6-mr6j\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF repo golang-jwt/jwt GHSA-mh63-6h87-95cp\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF all golang-jwt/jwt -o ./jwt-advisories\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF --config publisher.json repo golang-jwt/jwt GHSA-mh63-6h87-95cp\n")
	fmt.Fprintf(os.Stderr, "  ghsaToCSAF https://github.com/advisories/GHSA-cpj6-fhp6-mr6j\n")
}

// options holds the flags that are accepted both before and after the subcommand.
type options struct {
	output string
	config string
}

// parseFlags parses the subcommand arguments, using values given before the subcommand as defaults.
func parseFlags(name string, args []string, opts *options) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.StringVar(&opts.output, "o", opts.output, "Output destination")
	fs.StringVar(&opts.config, "config", opts.config, "Path to JSON config file")
	fs.Parse(args)
	return fs
}

func main() {
	// Root flags
	var opts options
	flag.StringVar(&opts.output, "o", "", "Output destination")
	flag.StringVar(&opts.config, "config", "", "Path to JSON config file")
	flag.Usage = printUsage
	flag.Parse()

	if flag.NArg() == 0 {
		printUsage()
		os.Exit(1)
	}

	command := flag.Arg(0)
	remainingArgs := flag.Args()[1:]

	var input string
	var err error

	switch strings.ToLower(command) {
	case "global":
		input, err = handleGlobal(remainingArgs, &opts)
	case "repository", "repo":
		input, err = handleRepository(remainingArgs, &opts)
	case "allofrepository", "all", "list":
		input, err = handleAll(remainingArgs, &opts)
	case "auto":
		input, err = handleAuto(remainingArgs, &opts)
	case "help":
		printUsage()
		os.Exit(0)
	default:
		// Use auto-detection for anything else
		input, err = handleAuto(flag.Args(), &opts)
	}

	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}

	// Load the config before downloading so that a broken config fails fast.
	var cfg *config.Config
	if opts.config != "" {
		cfg, err = config.Load(opts.config)
		if err != nil {
			fmt.Printf("Error: %v\n", err)
			os.Exit(1)
		}
	}

	advisories, err := downloader.FetchAdvisories(input)
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		os.Exit(1)
	}
	output := opts.output

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

	runConversion(advisories, output, cfg)
}

// handleGlobal handles the 'global' subcommand to fetch a specific advisory from the global GitHub database.
func handleGlobal(args []string, opts *options) (string, error) {
	fs := parseFlags("global", args, opts)

	if fs.NArg() < 1 {
		return "", fmt.Errorf("global command requires an ID or URL")
	}
	return fs.Arg(0), nil
}

// handleRepository handles the 'repository' subcommand to fetch a specific security advisory from a repository.
func handleRepository(args []string, opts *options) (string, error) {
	fs := parseFlags("repository", args, opts)

	if fs.NArg() < 1 {
		return "", fmt.Errorf("repository command requires at least <owner/repo>")
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

	return input, nil
}

// handleAll handles the 'allOfRepository' subcommand to fetch all published advisories for a given repository.
func handleAll(args []string, opts *options) (string, error) {
	fs := parseFlags("allOfRepository", args, opts)

	if fs.NArg() < 1 {
		return "", fmt.Errorf("allOfRepository command requires <owner/repo>")
	}
	return fs.Arg(0), nil
}

// handleAuto handles input type auto-detection and maintains backward compatibility for legacy positional arguments.
func handleAuto(args []string, opts *options) (string, error) {
	fs := parseFlags("auto", args, opts)

	if fs.NArg() < 1 {
		return "", fmt.Errorf("no input provided")
	}

	// In auto mode, we might have ghsa <input> <output> for legacy support
	input := fs.Arg(0)
	if opts.output == "" && fs.NArg() >= 2 {
		opts.output = fs.Arg(1)
	}

	return input, nil
}

// runConversion iterates through fetched advisories, converts them to CSAF, and saves them to the specified output.
func runConversion(advisories []ghsa.GHSAAdvisory, output string, cfg *config.Config) {
	outputBase := output
	isDir := false
	if outputBase != "" {
		if info, err := os.Stat(outputBase); err == nil && info.IsDir() {
			isDir = true
		}
	}

	successCount := 0
	for _, adv := range advisories {
		// Convert GHSA to CSAF
		csafa, err := converter.ToCSAF(adv, cfg)
		if err != nil {
			slog.Error("Error converting GHSA to CSAF",
				slog.String("GHSA ID", adv.GetGhsaID()),
				slog.Any("error", err))
			continue
		}

		// Determine filename
		var filename string
		if outputBase == "" {
			// Default output filename if not provided
			filename = strings.ToLower(adv.GetGhsaID()) + ".json"
		} else if isDir {
			// Systematic directory output
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
