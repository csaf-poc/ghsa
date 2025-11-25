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
			name: "correct split",
			args: args{packageName: "github.com/golang-jwt/jwt/v5"},
			want: utils.Ref("jwt"),
		},
		{
			name: "Only one split",
			args: args{packageName: "github.com/something"},
			want: utils.Ref("github.com/something"),
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
