package downloader

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/csaf-poc/ghsa/models/ghsa"
	"github.com/csaf-poc/ghsa/models/ghsa/global"
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

// FetchAdvisories retrieves one or more advisories based on the provided URL.
// It supports global advisories, single repository advisories, and repository advisory listings.
func FetchAdvisories(url string) ([]ghsa.GHSAAdvisory, error) {
	normalizedURL, isGlobal, isListing, err := normalizeGHSAURL(url)
	if err != nil {
		return nil, fmt.Errorf("invalid URL: %v", err)
	}

	// If it's a listing, fetch all advisories.
	if isListing {
		owner, repo, ok := parseRepositoryInput(url)
		if !ok {
			// This should not happen if normalizeGHSAURL succeeded for listing
			return nil, fmt.Errorf("could not parse repository from URL: %s", url)
		}
		return ListRepositoryAdvisories(owner, repo)
	}

	// Otherwise, it's a single advisory (global or repository).
	adv, err := DownloadGHSAFromAPI(normalizedURL, isGlobal)
	if err != nil {
		return nil, err
	}
	return []ghsa.GHSAAdvisory{adv}, nil
}

// DownloadGHSA fetches and unmarshals a GHSA advisory from a browser or API URL
// It handles both browser and API URL formats (repository and global), normalizes them,
// makes an HTTP GET request, and unmarshals the JSON response into the appropriate struct.
// Returns a GHSAAdvisory interface or an error.
func DownloadGHSA(url string) (adv ghsa.GHSAAdvisory, err error) {
	// Normalize URL to standard API format
	normalizedURL, isGlobal, _, err := normalizeGHSAURL(url)
	if err != nil {
		err = fmt.Errorf("invalid URL: %v", err)
		return nil, err
	}

	return DownloadGHSAFromAPI(normalizedURL, isGlobal)
}

// DownloadGHSAFromAPI fetches and unmarshals a GHSA advisory from a normalized API URL.
func DownloadGHSAFromAPI(normalizedURL string, isGlobal bool) (adv ghsa.GHSAAdvisory, err error) {
	slog.Info("Downloading GitHub Security Advisory (GHSA)",
		slog.String("URL", normalizedURL))

	// Fetch the advisory from GitHub API
	resp, err := http.Get(normalizedURL)
	if err != nil {
		err = fmt.Errorf("could not create request due to network error: '%v'", err)
		return
	}
	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("could not get GitHub URL. Status code is '%s'", resp.Status)
		return
	}
	defer resp.Body.Close()

	// Read and unmarshal the response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("could not read response body: %v", err)
		return nil, err
	}

	if isGlobal {
		var g global.Advisory
		err = json.Unmarshal(body, &g)
		if err != nil {
			err = fmt.Errorf("could not unmarshal global advisory: %v", err)
			return nil, err
		}
		adv = &g
	} else {
		var r repository.Advisory
		err = json.Unmarshal(body, &r)
		if err != nil {
			err = fmt.Errorf("could not unmarshal repository advisory: %v", err)
			return nil, err
		}
		adv = &r
	}

	return adv, nil
}

// normalizeGHSAURL converts a browser GHSA URL to its canonical API endpoint form.
// It supports both repository-level and global advisories.
// Returns the normalized API URL, a boolean indicating if it's a global advisory,
// a boolean indicating if it's a listing, and an error.
func normalizeGHSAURL(ghsaURL string) (apiURL string, isGlobal bool, isListing bool, err error) {
	trimmed := strings.TrimRight(strings.TrimSpace(ghsaURL), "/")

	// 0. Check for bare GHSA ID
	if strings.HasPrefix(strings.ToUpper(trimmed), "GHSA-") {
		apiURL = fmt.Sprintf("https://api.github.com/advisories/%s", trimmed)
		isGlobal = true
		isListing = false
		return
	}

	// Accept scheme-less pastes such as "github.com/OWNER/REPO". Without a scheme
	// url.Parse treats the host as the first path segment.
	if !strings.Contains(trimmed, "://") &&
		(strings.HasPrefix(trimmed, "github.com/") || strings.HasPrefix(trimmed, "api.github.com/")) {
		trimmed = "https://" + trimmed
	}

	u, err := url.Parse(trimmed)
	if err != nil {
		err = fmt.Errorf("invalid URL: %w", err)
		return
	}

	// Split path into parts, removing leading/trailing slashes.
	parts := strings.Split(strings.Trim(u.Path, "/"), "/")

	// 1. Check for global advisory format.
	// Browser: https://github.com/advisories/GHSA-xxxx-xxxx-xxxx
	// API:     https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx
	if (u.Host == "github.com" || u.Host == "api.github.com") &&
		len(parts) >= 2 && parts[0] == "advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/advisories/%s", parts[1])
		isGlobal = true
		isListing = false
		return
	}

	// 2. Check for single repository advisory format.
	// Browser: https://github.com/OWNER/REPO/security/advisories/GHSA_ID
	// API:     https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID
	if u.Host == "github.com" && len(parts) == 5 && parts[2] == "security" && parts[3] == "advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories/%s", parts[0], parts[1], parts[4])
		isGlobal = false
		isListing = false
		return
	}

	if u.Host == "api.github.com" && len(parts) == 5 && parts[0] == "repos" && parts[3] == "security-advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories/%s", parts[1], parts[2], parts[4])
		isGlobal = false
		isListing = false
		return
	}

	// 3. Check for repository advisory listing format.
	if owner, repo, ok := parseRepositoryInput(trimmed); ok {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories", owner, repo)
		isGlobal = false
		isListing = true
		return
	}

	err = fmt.Errorf("unsupported URL: %s. Expected repository or global advisory URL", ghsaURL)
	return
}

// parseRepositoryInput recognizes the repository-level layout and extracts owner
// and repository name.
func parseRepositoryInput(input string) (owner, repo string, ok bool) {
	u, err := url.Parse(input)
	if err != nil {
		return "", "", false
	}

	parts := strings.Split(strings.Trim(u.Path, "/"), "/")
	for _, p := range parts {
		if p == "" {
			return "", "", false
		}
	}

	switch strings.ToLower(u.Host) {
	case "github.com":
		// OWNER/REPO — but never advisories/GHSA-xxxx, which is a global advisory.
		if len(parts) == 2 && parts[0] != "advisories" {
			return parts[0], strings.TrimSuffix(parts[1], ".git"), true
		}
		// OWNER/REPO/security/advisories
		if len(parts) == 4 && parts[2] == "security" && parts[3] == "advisories" {
			return parts[0], parts[1], true
		}
	case "api.github.com":
		// repos/OWNER/REPO
		if len(parts) == 3 && parts[0] == "repos" {
			return parts[1], parts[2], true
		}
		// repos/OWNER/REPO/security-advisories
		if len(parts) == 4 && parts[0] == "repos" && parts[3] == "security-advisories" {
			return parts[1], parts[2], true
		}
	case "":
		// Bare OWNER/REPO
		if len(parts) == 2 && parts[0] != "advisories" {
			return parts[0], strings.TrimSuffix(parts[1], ".git"), true
		}
	}

	return "", "", false
}
