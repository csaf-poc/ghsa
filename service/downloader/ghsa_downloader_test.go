package downloader

import (
	"testing"

	"github.com/csaf-poc/ghsa/models/ghsa"
	"github.com/stretchr/testify/assert"
)

func TestDownloadGHSA(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name     string
		args     args
		wantGhsa assert.ValueAssertionFunc
		wantErr  assert.ErrorAssertionFunc
	}{
		{
			name: "Happy path: Valid GHSA URL",
			args: args{
				url: "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
			},
			wantGhsa: func(t assert.TestingT, got interface{}, want ...interface{}) bool {
				gotGhsa, ok := got.(ghsa.GHSAAdvisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want ghsa.GHSAAdvisory", got)
					return false
				}
				if wantID := "GHSA-mh63-6h87-95cp"; gotGhsa.GetGhsaID() != wantID {
					t.Errorf("DownloadGHSA() gotGhsa.GetGhsaID() = '%v', want.GetGhsaID() '%v'", gotGhsa.GetGhsaID(), wantID)
					return false
				}
				if wantCveId := "CVE-2025-30204"; gotGhsa.GetCveID() != wantCveId {
					t.Errorf("DownloadGHSA() gotGhsa.GetCveID() = '%v', want.GetCveID() '%v'", gotGhsa.GetCveID(), wantCveId)
					return false
				}
				return true
			},
			wantErr: assert.NoError,
		},
		{
			name: "Err: Check URL fails",
			args: args{
				url: "https://api.gitlb.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			wantGhsa: func(t assert.TestingT, got interface{}, want ...interface{}) bool {
				if got == nil {
					return true
				}
				gotGhsa, ok := got.(ghsa.GHSAAdvisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want ghsa.GHSAAdvisory", got)
					return false
				}
				return gotGhsa == nil
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "unsupported URL")
			},
		},
		{
			name: "Err: Get URL fails",
			args: args{
				url: "https://api.github.com/repos/golang-jwt/jwt/security-advisories/This-Is-Not-A-GHSA",
			},
			wantGhsa: func(t assert.TestingT, got interface{}, want ...interface{}) bool {
				if got == nil {
					return true
				}
				gotGhsa, ok := got.(ghsa.GHSAAdvisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want ghsa.GHSAAdvisory", got)
					return false
				}
				return gotGhsa == nil
			},
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.ErrorContains(t, err, "404 Not Found")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGhsa, err := DownloadGHSA(tt.args.url)
			if !tt.wantErr(t, err) {
				t.Error("Testing DownloadGHSA(): tt.wantErr() didn't run as expected") // TODO: Check error case
			}
			if !tt.wantGhsa(t, gotGhsa) {
				t.Error("Testing DownloadGHSA(): tt.wantGhsa() didn't run as expected") // TODO: Check error case
			}
		})
	}
}

func TestCheckURL(t *testing.T) {
	type args struct {
		urlStr string
	}
	tests := []struct {
		name         string
		args         args
		want         string
		wantIsGlobal bool
		wantErr      assert.ErrorAssertionFunc
	}{
		{
			name: "Valid API URL",
			args: args{
				urlStr: "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			want:         "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			wantIsGlobal: false,
			wantErr:      assert.NoError,
		},
		{
			name: "Valid Browser URL",
			args: args{
				urlStr: "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
			},
			want:         "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			wantIsGlobal: false,
			wantErr:      assert.NoError,
		},
		{
			name: "Invalid API URL format (missing 'repos' part)",
			args: args{
				urlStr: "https://api.github.com/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			want:         "",
			wantIsGlobal: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "unsupported URL")
			},
		},
		{
			name: "Wrong URL format",
			args: args{
				urlStr: "https://gitlab.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
			},
			want:         "",
			wantIsGlobal: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "unsupported URL")
			},
		},
		{
			name: "Invalid URL (parsing error)",
			args: args{
				urlStr: ":",
			},
			want:         "",
			wantIsGlobal: false,
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "invalid URL")
			},
		},
		{
			name: "Global browser URL",
			args: args{
				urlStr: "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx",
			},
			want:         "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx",
			wantIsGlobal: true,
			wantErr:      assert.NoError,
		},
		{
			name: "Global API URL",
			args: args{
				urlStr: "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx",
			},
			want:         "https://api.github.com/advisories/GHSA-xxxx-xxxx-xxxx",
			wantIsGlobal: true,
			wantErr:      assert.NoError,
		},
		{
			name: "Repository listing browser URL",
			args: args{
				urlStr: "https://github.com/OWNER/REPO",
			},
			want:         "https://api.github.com/repos/OWNER/REPO/security-advisories",
			wantIsGlobal: false,
			wantErr:      assert.NoError,
		},
		{
			name: "Repository security advisories browser URL",
			args: args{
				urlStr: "https://github.com/OWNER/REPO/security/advisories",
			},
			want:         "https://api.github.com/repos/OWNER/REPO/security-advisories",
			wantIsGlobal: false,
			wantErr:      assert.NoError,
		},
		{
			name: "Bare OWNER/REPO",
			args: args{
				urlStr: "OWNER/REPO",
			},
			want:         "https://api.github.com/repos/OWNER/REPO/security-advisories",
			wantIsGlobal: false,
			wantErr:      assert.NoError,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, gotIsGlobal, err := normalizeGHSAURL(tt.args.urlStr)
			tt.wantErr(t, err)
			if got != tt.want {
				t.Errorf("normalizeGHSAURL() got = %v, want %v", got, tt.want)
			}
			if gotIsGlobal != tt.wantIsGlobal {
				t.Errorf("normalizeGHSAURL() gotIsGlobal = %v, want %v", gotIsGlobal, tt.wantIsGlobal)
			}
		})
	}
}
