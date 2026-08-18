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

// DownloadGHSA fetches and unmarshals a GHSA advisory from a browser or API URL
// It handles both browser and API URL formats (repository and global), normalizes them,
// makes an HTTP GET request, and unmarshals the JSON response into the appropriate struct.
// Returns a GHSAAdvisory interface or an error.
func DownloadGHSA(url string) (adv ghsa.GHSAAdvisory, err error) {
	slog.Info("Downloading GitHub Security Advisory (GHSA)",
		slog.String("URL", url))
	// Normalize URL to standard API format
	normalizedURL, isGlobal, err := normalizeGHSAURL(url)
	if err != nil {
		err = fmt.Errorf("invalid URL: %v", err)
		return nil, err
	}

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
// Returns the normalized API URL, a boolean indicating if it's a global advisory, and an error.
func normalizeGHSAURL(ghsaURL string) (apiURL string, isGlobal bool, err error) {
	var (
		u *url.URL
	)

	u, err = url.Parse(ghsaURL)
	if err != nil {
		err = fmt.Errorf("invalid URL: %w", err)
		return
	}

	// Split URL into parts
	parts := strings.Split(u.Path, "/")

	// Check for global advisory browser format (https://github.com/advisories/GHSA-xxxx-xxxx-xxxx)
	if u.Host == "github.com" && len(parts) == 3 && parts[1] == "advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/advisories/%s", parts[2])
		isGlobal = true
		return
	}

	// Check for global API format (https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx)
	if u.Host == "api.github.com" && len(parts) == 3 && parts[1] == "advisories" {
		apiURL = ghsaURL
		isGlobal = true
		return
	}

	// Check for repository browser format (https://github.com/OWNER/REPO/security/advisories/GHSA_ID)
	if u.Host == "github.com" && len(parts) == 6 && parts[3] == "security" && parts[4] == "advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories/%s", parts[1], parts[2], parts[5])
		isGlobal = false
		return
	}

	// Check for repository API format (https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID)
	if u.Host == "api.github.com" && len(parts) == 6 && parts[1] == "repos" && parts[4] == "security-advisories" {
		apiURL = ghsaURL
		isGlobal = false
		return
	}

	// Unsupported URL format
	err = fmt.Errorf("unsupported URL: %s. Expected repository or global advisory URL", ghsaURL)
	return
}
