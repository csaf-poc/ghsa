package internal

import (
	"testing"

	ghsarepository "github.com/csaf-poc/ghsa/models/ghsa/repository"
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
				url: "https://github.com/esm-dev/esm.sh/security/advisories/GHSA-h3mw-4f23-gwpw",
			},
			wantGhsa: func(t assert.TestingT, got interface{}, want ...interface{}) bool {
				gotGhsa, ok := got.(*ghsarepository.Advisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want *ghsarepository.Advisory", got)
					return false
				}
				if wantID := "GHSA-mh63-6h87-95cp"; gotGhsa.GhsaID != wantID {
					t.Errorf("DownloadGHSA() gotGhsa.GhsaID = '%v', want.GhsaID '%v'", gotGhsa.GhsaID, wantID)
					return false
				}
				if wantCveId := "CVE-2025-30204"; gotGhsa.CveID != wantCveId {
					t.Errorf("DownloadGHSA() gotGhsa.CveID = '%v', want.CveID '%v'", gotGhsa.CveID, wantCveId)
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
				gotGhsa, ok := got.(*ghsarepository.Advisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want *ghsarepository.Advisory", got)
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
				gotGhsa, ok := got.(*ghsarepository.Advisory)
				if !ok {
					t.Errorf("DownloadGHSA() got = %v, want *ghsarepository.Advisory", got)
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
		name    string
		args    args
		want    string
		wantErr assert.ErrorAssertionFunc
	}{
		{
			name: "Valid API URL",
			args: args{
				urlStr: "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			want:    "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			wantErr: assert.NoError,
		},
		{
			name: "Valid Browser URL",
			args: args{
				urlStr: "https://github.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
			},
			want:    "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			wantErr: assert.NoError,
		},
		{
			name: "Invalid API URL format (missing 'repos' part)",
			args: args{
				urlStr: "https://api.github.com/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			want: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "unsupported URL")
			},
		},
		{
			name: "Wrong URL format",
			args: args{
				urlStr: "https://gitlab.com/golang-jwt/jwt/security/advisories/GHSA-mh63-6h87-95cp",
			},
			want: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "unsupported URL")
			},
		},
		{
			name: "Invalid URL (parsing error)",
			args: args{
				urlStr: ":",
			},
			want: "",
			wantErr: func(t assert.TestingT, err error, i ...interface{}) bool {
				return assert.Contains(t, err.Error(), "invalid URL")
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := normalizeGHSAURL(tt.args.urlStr)
			tt.wantErr(t, err)
			if got != tt.want {
				t.Errorf("normalizeGHSAURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}
