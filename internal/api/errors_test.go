package api

import (
	"fmt"
	"testing"
)

func TestIsMachineForbidden(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"machine 403", fmt.Errorf("x: %w", &HTTPError{Status: 403, Body: `{"detail":"machine_account_forbidden"}`}), true},
		{"other 403", &HTTPError{Status: 403, Body: `{"detail":"nope"}`}, false},
		{"401 same detail", &HTTPError{Status: 401, Body: `{"detail":"machine_account_forbidden"}`}, false},
		{"not an API error", fmt.Errorf("boom"), false},
		{"nil", nil, false},
	}
	for _, tt := range tests {
		if got := IsMachineForbidden(tt.err); got != tt.want {
			t.Errorf("%s: got %v, want %v", tt.name, got, tt.want)
		}
	}
}
