package auth

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/pkg/config"
)

// memTokenStore is the store a program importing the core gives.
type memTokenStore struct{ tok *oauth2.Token }

func (m *memTokenStore) Load() (*oauth2.Token, error) {
	if m.tok == nil {
		return nil, os.ErrNotExist
	}

	return m.tok, nil
}

func (m *memTokenStore) Save(tok *oauth2.Token) error {
	m.tok = tok

	return nil
}

func (m *memTokenStore) Delete() error {
	m.tok = nil

	return nil
}

// useTokenStore sets s for the test, and the store of the CLI back after it.
func useTokenStore(t *testing.T, s TokenStore) {
	t.Helper()
	SetTokenStore(s)
	t.Cleanup(func() { SetTokenStore(config.TokenFile{}) })
}

// Without a store, nothing is read or written: not logged in.
func TestGetValidTokenWithoutStore(t *testing.T) {
	t.Setenv(config.EnvTokenName, "")
	t.Setenv(config.EnvConfigDirName, t.TempDir())
	if err := config.SaveToken(&oauth2.Token{AccessToken: "on-disk", Expiry: time.Now().Add(time.Hour)}); err != nil {
		t.Fatal(err)
	}
	useTokenStore(t, nil)

	_, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("GetValidToken() error = %v, want ErrNoToken (token.json must not be read)", err)
	}
	if err := Tokens().Save(&oauth2.Token{}); !errors.Is(err, ErrNoTokenStore) {
		t.Errorf("Save() error = %v, want ErrNoTokenStore", err)
	}
	if _, err := Tokens().Load(); !errors.Is(err, os.ErrNotExist) {
		t.Errorf("Load() error = %v, want os.ErrNotExist", err)
	}
}

// An expired token is refreshed and the new one saved to the injected store.
func TestGetValidTokenInjectedStore(t *testing.T) {
	t.Setenv(config.EnvTokenName, "")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(TokenResponse{ //nolint:gosec // G117: test fixture, not real credentials
			AccessToken: "fresh", TokenType: "Bearer", RefreshToken: "r2", ExpiresIn: 3600,
		})
	}))
	defer srv.Close()
	store := &memTokenStore{tok: &oauth2.Token{
		AccessToken: "old", RefreshToken: "r1", Expiry: time.Now().Add(-time.Hour),
	}}
	useTokenStore(t, store)

	tok, err := GetValidToken(context.Background(), config.OIDCConfig{TokenURL: srv.URL}, http.DefaultClient)
	if err != nil {
		t.Fatalf("GetValidToken() error = %v", err)
	}
	if tok.AccessToken != "fresh" || store.tok.RefreshToken != "r2" {
		t.Errorf("token = %q, stored refresh = %q, want fresh and r2", tok.AccessToken, store.tok.RefreshToken)
	}
}
