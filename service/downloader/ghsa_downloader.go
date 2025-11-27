package downloader

import (
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	ghsarepository "github.com/csaf-poc/ghsa/models/ghsa/repository"
)

// DownloadGHSA fetches and unmarshals a GHSA advisory from a browser or API URL
// It handles both browser and API URL formats, normalizes them to the API format,
// makes an HTTP GET request, and unmarshals the JSON response into an Advisory struct.
// Returns the Advisory or an error if normalization, network request, or unmarshaling fails.
func DownloadGHSA(url string) (ghsa *ghsarepository.Advisory, err error) {
	slog.Info("Downloading GitHub Security Advisory (GHSA)",
		slog.String("URL", url))
	// Normalize URL to standard API format (accepts both browser and API URLs)
	url, err = normalizeGHSAURL(url)
	if err != nil {
		err = fmt.Errorf("invalid URL: %v", err)
		return nil, err
	}

	// Fetch the advisory from GitHub API
	resp, err := http.Get(url)
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
	err = json.Unmarshal(body, &ghsa)
	if err != nil {
		err = fmt.Errorf("could not unmarshal response body: %v", err)
		return nil, err
	}
	return ghsa, nil
}

// normalizeGHSAURL converts a browser GHSA URL to its canonical API endpoint form
// It accepts both browser URLs (github.com/OWNER/REPO/security/advisories/GHSA_ID)
// and API URLs (api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID),
// returning the normalized API URL format.
func normalizeGHSAURL(ghsaURL string) (apiURL string, err error) {
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

	// Check for browser format (https://github.com/OWNER/REPO/security/advisories/GHSA_ID)
	if u.Host == "github.com" && len(parts) == 6 && parts[3] == "security" && parts[4] == "advisories" {
		apiURL = fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories/%s", parts[1], parts[2], parts[5])
		return
	}

	// Check for API format (api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID)
	if u.Host == "api.github.com" && len(parts) == 6 && parts[1] == "repos" && parts[4] == "security-advisories" {
		// ghsaURL is already in the correct format
		apiURL = ghsaURL
		return
	}

	// Unsupported URL format
	err = fmt.Errorf("unsupported URL: %s. Expected `%s` or `%s`", ghsaURL, "https://github.com/OWNER/REPO/security/advisories/GHSA_ID", "https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID")
	return
}
