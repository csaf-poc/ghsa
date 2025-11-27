package utils

import "testing"

func TestRef(t *testing.T) {
	cases := []struct {
		name string
		in   interface{}
	}{
		{name: "int", in: 42},
		{name: "string", in: "hello"},
	}
	for _, tc := range cases {
		// We rely on type inference by assigning to a typed variable inside the loop
		t.Run(tc.name, func(t *testing.T) {
			switch v := tc.in.(type) {
			case int:
				p := Ref(v)
				if p == nil || *p != v {
					t.Errorf("Ref(int) = %v, want %v", p, v)
				}
			case string:
				p := Ref(v)
				if p == nil || *p != v {
					t.Errorf("Ref(string) = %v, want %v", p, v)
				}
			default:
				// Should not happen in these cases
				t.Fatalf("unexpected type: %T", v)
			}
		})
	}
}

func TestDeref(t *testing.T) {
	cases := []struct {
		name string
		in   *int
		want int
	}{
		{name: "non-nil", in: Ref(7), want: 7},
		{name: "nil", in: nil, want: 0}, // zero value for int
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := Deref(tc.in)
			if got != tc.want {
				t.Errorf("Deref() = %v, want %v", got, tc.want)
			}
		})
	}
}
