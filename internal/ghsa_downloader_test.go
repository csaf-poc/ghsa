package internal

import (
	ghsarepository "github.com/csaf-poc/ghsa/models/ghsa/repository"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestDownloadGHSA(t *testing.T) {
	type args struct {
		url string
	}
	tests := []struct {
		name     string
		args     args
		wantGhsa *ghsarepository.Advisory
		wantErr  bool
	}{
		{
			name: "Valid GHSA URL",
			args: args{
				url: "https://api.github.com/repos/golang-jwt/jwt/security-advisories/GHSA-mh63-6h87-95cp",
			},
			wantGhsa: &ghsarepository.Advisory{
				GhsaID: "GHSA-mh63-6h87-95cp",
				CveID:  "CVE-2025-30204",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotGhsa, err := DownloadGHSA(tt.args.url)
			if (err != nil) != tt.wantErr {
				t.Errorf("DownloadGHSA() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if gotID, wantID := gotGhsa.GhsaID, tt.wantGhsa.GhsaID; gotID != wantID {
				t.Errorf("DownloadGHSA() gotGhsa.GhsaID = %v, want.GhsaID %v", gotGhsa.GhsaID, tt.wantGhsa.GhsaID)
			}
			if gotCVE, wantCVE := gotGhsa.CveID, tt.wantGhsa.CveID; gotCVE != wantCVE {
				t.Errorf("DownloadGHSA() gotGhsa.CveID = %v, want.CveID %v", gotCVE, wantCVE)
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
				return assert.Contains(t, err.Error(), "invalid API URL format")
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
			got, err := checkURL(tt.args.urlStr)
			tt.wantErr(t, err)
			if got != tt.want {
				t.Errorf("checkURL() got = %v, want %v", got, tt.want)
			}
		})
	}
}
