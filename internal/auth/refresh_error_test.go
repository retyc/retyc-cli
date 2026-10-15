package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
)

// What a refresh that failed says of the login: lost for good only when the
// identity provider refused it, never when it could not be asked.
func TestRefresh_PermanentOrTransient(t *testing.T) {
	cases := map[string]struct {
		status    int
		body      string
		permanent bool
		sentinel  bool
	}{
		"invalid_grant":           {http.StatusBadRequest, `{"error":"invalid_grant"}`, true, true},
		"invalid_client":          {http.StatusUnauthorized, `{"error":"invalid_client"}`, true, false},
		"4xx without a body":      {http.StatusForbidden, `<html>forbidden</html>`, true, false},
		"5xx of the provider":     {http.StatusInternalServerError, `{"error":"server_error"}`, false, false},
		"gateway page":            {http.StatusBadGateway, `<html>bad gateway</html>`, false, false},
		"throttled":               {http.StatusTooManyRequests, `Too Many Requests`, false, false},
		"temporarily unavailable": {http.StatusBadRequest, `{"error":"temporarily_unavailable"}`, false, false},
		"unreadable 200":          {http.StatusOK, `<html>portal</html>`, false, false},
	}
	for label, tc := range cases {
		t.Run(label, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			_, err := Refresh(context.Background(), config.OIDCConfig{ClientID: "test", TokenURL: srv.URL},
				"refresh", http.DefaultClient)
			if err == nil {
				t.Fatal("Refresh() = nil, want an error")
			}
			// As RefreshingTokenSource.Token wraps it.
			err = fmt.Errorf("refreshing token: %w", err)
			if got := IsPermanent(err); got != tc.permanent {
				t.Errorf("IsPermanent(%v) = %v, want %v", err, got, tc.permanent)
			}
			if got := errors.Is(err, ErrNoRefreshToken); got != tc.sentinel {
				t.Errorf("errors.Is(%v, ErrNoRefreshToken) = %v, want %v", err, got, tc.sentinel)
			}
		})
	}

	// The provider cannot be reached at all.
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	_, err := Refresh(context.Background(), config.OIDCConfig{ClientID: "test", TokenURL: url},
		"refresh", http.DefaultClient)
	if err == nil || IsPermanent(err) {
		t.Errorf("IsPermanent(%v) = true for a provider that cannot be reached", err)
	}
	for _, sentinel := range []error{ErrNoToken, ErrNoRefreshToken} {
		if !IsPermanent(fmt.Errorf("wrapped: %w", sentinel)) {
			t.Errorf("IsPermanent(%v) = false", sentinel)
		}
	}
	if IsPermanent(context.DeadlineExceeded) {
		t.Error("a timeout is taken for a login lost")
	}
}
