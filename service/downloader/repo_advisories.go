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
	"github.com/csaf-poc/ghsa/models/ghsa/repository"
)

const (
	// githubAPIVersion pins the REST API version we were developed against, as
	// documented for "List repository security advisories".
	//
	// The header is not mandatory: omitting it also returns 200 with an identical
	// payload, because GitHub then applies its own default version. We still send
	// it so that a future change of that default cannot silently alter the
	// response shape we unmarshal. An unknown value is rejected with 400, so the
	// value is validated rather than ignored.
	githubAPIVersion = "2026-03-10"

	// advisoryPageSize is the page size requested per listing call. The endpoint
	// documents a default of 30 and no maximum; 100 is GitHub's usual cap.
	advisoryPageSize = 100

	// advisoryState restricts the listing to published advisories.
	//
	// The endpoint also serves `draft` and `triage` advisories to callers with
	// sufficient permissions, but those are embargoed, not-yet-public
	// vulnerability reports and converting them is wrong for two reasons:
	// CSAF requires `/document/tracking/initial_release_date`, which is derived
	// from `published_at` and is null while unpublished; and the converter emits
	// `/document/tracking/status` as `final`, which would misstate a draft.
	// Exposing other states needs an explicit opt-in flag, not a default.
	advisoryState = "published"

	// maxAdvisoryPages bounds the pagination walk so that a malformed or looping
	// Link header cannot spin forever against the API.
	maxAdvisoryPages = 100
)

// ListRepositoryAdvisories fetches all published security advisories for a
// repository via GET /repos/{owner}/{repo}/security-advisories.
//
// Each returned advisory is an independent GHSA and therefore converts into its
// own CSAF document: `/document/tracking/id` is single-valued and must be unique
// per issuing party, and CSAF derives the document filename from it (spec 5.1).
//
// Requests are unauthenticated, which limits us to published advisories of
// public repositories and to 60 requests/hour. That is exactly the data this
// function asks for; token support is a later addition (see README).
func ListRepositoryAdvisories(owner, repo string) (advisories []ghsa.GHSAAdvisory, err error) {
	slog.Info("Listing repository security advisories",
		slog.String("owner", owner),
		slog.String("repository", repo),
		slog.String("state", advisoryState))

	startURL := fmt.Sprintf("https://api.github.com/repos/%s/%s/security-advisories?per_page=%d&state=%s",
		url.PathEscape(owner), url.PathEscape(repo), advisoryPageSize, advisoryState)

	all, err := listAdvisoryPages(startURL)
	if err != nil {
		return nil, err
	}

	// Address the slice elements rather than a loop copy, so every interface
	// value points at a distinct advisory.
	advisories = make([]ghsa.GHSAAdvisory, len(all))
	for i := range all {
		advisories[i] = &all[i]
	}

	slog.Info("Listed repository security advisories",
		slog.String("owner", owner),
		slog.String("repository", repo),
		slog.Int("advisories", len(advisories)))
	return advisories, nil
}

// listAdvisoryPages walks the cursor pagination from startURL and returns every
// advisory across all pages. It takes the start URL rather than owner/repo so the
// paging walk can be exercised against a local test server.
func listAdvisoryPages(startURL string) (all []repository.Advisory, err error) {
	// Collect every page into one slice before any pointers are handed out, so
	// the addresses taken by the caller stay valid after the final append.
	for pageURL, page := startURL, 1; pageURL != ""; page++ {
		if page > maxAdvisoryPages {
			err = fmt.Errorf("aborted after %d pages: the API kept offering a next-page cursor", maxAdvisoryPages)
			return nil, err
		}

		var (
			body       []byte
			linkHeader string
			batch      []repository.Advisory
		)
		body, linkHeader, err = getGitHubAPI(pageURL)
		if err != nil {
			return nil, err
		}
		if err = json.Unmarshal(body, &batch); err != nil {
			err = fmt.Errorf("could not unmarshal repository advisory list: %v", err)
			return nil, err
		}

		all = append(all, batch...)
		slog.Debug("Fetched advisory page",
			slog.Int("page", page),
			slog.Int("advisories in page", len(batch)),
			slog.Int("advisories so far", len(all)))

		pageURL = nextPageURL(linkHeader)
	}
	return all, nil
}

// getGitHubAPI performs an unauthenticated GET against the GitHub API and returns
// the response body together with the Link header used for paging.
func getGitHubAPI(apiURL string) (body []byte, linkHeader string, err error) {
	var (
		req  *http.Request
		resp *http.Response
	)

	req, err = http.NewRequest(http.MethodGet, apiURL, nil)
	if err != nil {
		err = fmt.Errorf("could not create request: %v", err)
		return nil, "", err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", githubAPIVersion)

	resp, err = http.DefaultClient.Do(req)
	if err != nil {
		err = fmt.Errorf("could not create request due to network error: '%v'", err)
		return nil, "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, "", statusError(resp)
	}

	body, err = io.ReadAll(resp.Body)
	if err != nil {
		err = fmt.Errorf("could not read response body: %v", err)
		return nil, "", err
	}

	return body, resp.Header.Get("Link"), nil
}

// statusError turns a non-200 response into an error, spelling out the two
// failure modes an operator can actually act on: rate limiting and no access.
func statusError(resp *http.Response) error {
	switch resp.StatusCode {
	case http.StatusForbidden, http.StatusTooManyRequests:
		if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			return fmt.Errorf("GitHub API rate limit exceeded (status '%s'): "+
				"unauthenticated requests are limited to 60 per hour, so wait for the window to reset", resp.Status)
		}
	case http.StatusNotFound:
		return fmt.Errorf("repository not found, or it is private (status '%s'): "+
			"only public repositories are supported because requests are unauthenticated", resp.Status)
	}
	return fmt.Errorf("could not get GitHub URL. Status code is '%s'", resp.Status)
}

// nextPageURL extracts the rel="next" target from a GitHub Link header.
//
// This endpoint paginates by opaque cursor (`before`/`after`) and has no `page`
// parameter, so following the header GitHub hands back is the only reliable way
// to walk it. An absent or next-less header ends the walk.
//
// Example header value:
//
//	<https://api.github.com/repositories/9384267/security-advisories?per_page=3&after=CURSOR>; rel="next"
func nextPageURL(linkHeader string) string {
	for _, link := range strings.Split(linkHeader, ",") {
		parts := strings.Split(link, ";")
		if len(parts) < 2 {
			continue
		}
		target := strings.TrimSpace(parts[0])
		if !strings.HasPrefix(target, "<") || !strings.HasSuffix(target, ">") {
			continue
		}
		for _, param := range parts[1:] {
			if isRelNext(param) {
				return target[1 : len(target)-1]
			}
		}
	}
	return ""
}

// isRelNext reports whether a Link header parameter is rel="next", tolerating
// surrounding whitespace and optional quoting.
func isRelNext(param string) bool {
	key, value, found := strings.Cut(param, "=")
	if !found {
		return false
	}
	if strings.TrimSpace(key) != "rel" {
		return false
	}
	return strings.Trim(strings.TrimSpace(value), `"`) == "next"
}
