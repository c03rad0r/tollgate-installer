package app

import "testing"

func TestValidNewRootPassword(t *testing.T) {
	for _, tc := range []struct {
		pw   string
		want bool
	}{
		{"", false},
		{"short", false},
		{"abcdefgh", true},
		{"a password with spaces", true},
		{"quote'd password", true},
		{"bad\npass", false},
		{"bad\x00pass", false},
		{string(make([]byte, 64)), false},
	} {
		if got := validNewRootPassword(tc.pw); got != tc.want {
			t.Errorf("validNewRootPassword(%q)=%v want %v", tc.pw, got, tc.want)
		}
	}
}
