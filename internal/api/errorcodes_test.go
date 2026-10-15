package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The client keeps the X-Error-Code of a refusal, and ErrorCode reads it
// through any wrapping; a refusal without the header has no code.
func TestResponseError_KeepsErrorCode(t *testing.T) {
	for _, code := range []string{CodeParentDeleted, ""} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			if code != "" {
				w.Header().Set(ErrorCodeHeader, code)
			}
			http.Error(w, `{"detail":"The parent folder is pending deletion"}`, http.StatusGone)
		}))
		err := newTestClient(srv).Get(context.Background(), "/x", nil)
		srv.Close()

		var httpErr *HTTPError
		if !errors.As(err, &httpErr) || httpErr.Code != code {
			t.Fatalf("code %q: err = %#v, want an HTTPError carrying the code", code, err)
		}
		if got := ErrorCode(fmt.Errorf("wrapped: %w", err)); got != code {
			t.Errorf("ErrorCode = %q, want %q", got, code)
		}
		if !errors.Is(err, ErrGone) || !errors.Is(err, ErrNotFound) {
			t.Errorf("code %q: err = %v, want ErrGone and ErrNotFound still matched", code, err)
		}
	}
	if got := ErrorCode(errors.New("not an API error")); got != "" {
		t.Errorf("ErrorCode of a plain error = %q", got)
	}
}

// The code decides when there is one; the former detail text only counts
// on a 400 without a code.
func TestIsStorageExceeded(t *testing.T) {
	oldDetail := `{"detail":"Upload exceeds maximum allowed storage size"}`
	for _, tc := range []struct {
		name string
		err  error
		want bool
	}{
		{"code", &HTTPError{Status: 400, Code: CodeStorageExceeded, Body: `{"detail":"Not enough storage"}`}, true},
		{"other code, old detail", &HTTPError{Status: 400, Code: CodeVersionsLimit, Body: oldDetail}, false},
		{"plan code", &HTTPError{Status: 400, Code: CodeStoragePlanExceeded, Body: oldDetail}, false},
		{"no code, old detail", &HTTPError{Status: 400, Body: oldDetail}, true},
		{"no code, other 400", &HTTPError{Status: 400, Body: `{"detail":"Maximum number of versions reached (3)"}`}, false},
		{"no code, old detail, not a 400", &HTTPError{Status: 422, Body: oldDetail}, false},
		{"not an API error", errors.New("exceeds maximum allowed storage size"), false},
	} {
		if got := IsStorageExceeded(fmt.Errorf("wrapped: %w", tc.err)); got != tc.want {
			t.Errorf("%s: IsStorageExceeded = %v, want %v", tc.name, got, tc.want)
		}
	}
}
