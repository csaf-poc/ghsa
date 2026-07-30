package converter

import (
	"reflect"
	"testing"

	"github.com/csaf-poc/ghsa/internal/utils"
)

func Test_getRepositoryName(t *testing.T) {
	type args struct {
		packageName string
	}
	tests := []struct {
		name string
		args args
		want *string
	}{
		{
			name: "github with go semver suffix",
			args: args{packageName: "github.com/golang-jwt/jwt/v5"},
			want: utils.Ref("jwt"),
		},
		{
			name: "github without version suffix",
			args: args{packageName: "github.com/foo/bar"},
			want: utils.Ref("bar"),
		},
		{
			name: "github with deep subpath",
			args: args{packageName: "github.com/foo/bar/baz/qux"},
			want: utils.Ref("bar"),
		},
		{
			name: "gitlab returns full name (subgroups possible)",
			args: args{packageName: "gitlab.com/foo/bar/v2"},
			want: utils.Ref("gitlab.com/foo/bar/v2"),
		},
		{
			name: "gitlab with subgroup returns full name",
			args: args{packageName: "gitlab.com/group/subgroup/repo"},
			want: utils.Ref("gitlab.com/group/subgroup/repo"),
		},
		{
			name: "bitbucket",
			args: args{packageName: "bitbucket.org/foo/bar"},
			want: utils.Ref("bar"),
		},
		{
			name: "github with only two segments returns full name",
			args: args{packageName: "github.com/something"},
			want: utils.Ref("github.com/something"),
		},
		{
			name: "go vanity import returns full name",
			args: args{packageName: "k8s.io/api"},
			want: utils.Ref("k8s.io/api"),
		},
		{
			name: "npm scoped package returns full name",
			args: args{packageName: "@babel/core"},
			want: utils.Ref("@babel/core"),
		},
		{
			name: "composer package returns full name",
			args: args{packageName: "symfony/http-foundation"},
			want: utils.Ref("symfony/http-foundation"),
		},
		{
			name: "npm bare package returns full name",
			args: args{packageName: "react-router"},
			want: utils.Ref("react-router"),
		},
		{
			name: "maven coordinate returns full name",
			args: args{packageName: "org.springframework:spring-core"},
			want: utils.Ref("org.springframework:spring-core"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := getRepositoryName(tt.args.packageName); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("getRepositoryName() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_normalizeOperators(t *testing.T) {
	cases := []struct {
		name string
		in   string
		out  string
	}{
		{name: "attached <=", in: "<=5.2.1", out: "less or equal 5.2.1"},
		{name: "attached >=", in: ">=1.0.0", out: "greater or equal 1.0.0"},
		{name: "range both sides", in: "1.0.0<=2.0.0", out: "1.0.0 less or equal 2.0.0"},
		{name: "mixed spaces", in: " <2.3.4  ", out: "less than 2.3.4"},
		{name: "greater than", in: ">2.3.4", out: "greater than 2.3.4"},
		{name: "no operators", in: "1.2.3", out: "1.2.3"},
	}
	for _, tc := range cases {
		got := normalizeOperators(tc.in)
		if got != tc.out {
			// Show debug diff style
			t.Errorf("normalizeOperators(%q) = %q, want %q", tc.in, got, tc.out)
		}
	}
}
