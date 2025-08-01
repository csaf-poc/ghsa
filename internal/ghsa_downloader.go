package internal

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	ghsarepository "github.com/csaf-poc/ghsa/models/ghsa/repository"
)

// API -> 			https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp
// Browesr URL -> 	https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp
const _ = "https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID"

// DownloadGHSA downloads a GHSA from the given URL and returns a ghsarepository.Advisory
func DownloadGHSA(url string) (ghsa *ghsarepository.Advisory, err error) {
	var jb map[string]interface{}

	url, err = checkURL(url)
	if err != nil {
		err = fmt.Errorf("invalid URL: %v", err)
		return nil, err
	}

	resp, err := http.Get(url)
	if err != nil || resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("could not create request due to network error or status is not ok: error is '%v' and status code is '%s'", err, resp.Status)
		return nil, err
	}

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
	sb := string(body)
	err = json.Unmarshal([]byte(sb), &jb)
	//prettyPrint(jb)
	return ghsa, nil
}

// checkURL checks if the provided URL is in a valid format for a GitHub Security Advisory
func checkURL(urlStr string) (string, error) {
	u, err := url.Parse(urlStr)
	if err != nil {
		return "", fmt.Errorf("invalid URL: %w", err)
	}

	// Check for browser format (https://github.com/OWNER/REPO/security/advisories/GHSA_ID)
	if u.Host == "github.com" {
		parts := strings.Split(u.Path, "/")
		// Expect: /OWNER/REPO/security/advisories/GHSA_ID
		if len(parts) == 6 && parts[3] == "security" && parts[4] == "advisories" {
			apiURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories/%s", parts[1], parts[2], parts[5])
			return apiURL, nil
		}
	}

	// Check for API format (api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID)
	if u.Host == "api.github.com" {
		parts := strings.Split(u.Path, "/")
		if len(parts) == 6 && parts[1] == "repos" && parts[4] == "security-advisories" {
			return urlStr, nil
		}
		err = fmt.Errorf("invalid API URL format: '%s'. Expected  '%s'", urlStr, "api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID")
		return "", err
	}

	err = fmt.Errorf("unsupported URL: %s. Expected `%s` or `%s`", urlStr, "https://github.com/OWNER/REPO/security/advisories/GHSA_ID", "https://api.github.com/repos/OWNER/REPO/security-advisories/GHSA_ID")
	return "", err
}

func prettyPrint(data interface{}) {
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		fmt.Println("Error:", err)
		return
	}
	fmt.Println(string(b))
}
