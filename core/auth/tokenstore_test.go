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

	"github.com/retyc/retyc-cli/core/config"
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
	t.Cleanup(func() { SetTokenStore(testTokenFile{}) })
}

// Without a store, nothing is read or written: not logged in.
func TestGetValidTokenWithoutStore(t *testing.T) {
	t.Setenv(config.EnvTokenName, "")
	t.Setenv(config.EnvConfigDirName, t.TempDir())
	if err := Tokens().Save(&oauth2.Token{AccessToken: "on-disk", Expiry: time.Now().Add(time.Hour)}); err != nil {
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

// failingTokenStore cannot be read: a locked vault, an I/O error.
type failingTokenStore struct{ memTokenStore }

var errVaultLocked = errors.New("vault locked")

func (*failingTokenStore) Load() (*oauth2.Token, error) { return nil, errVaultLocked }

// A store that fails still reads as "not logged in", and says why.
func TestGetValidTokenFailingStore(t *testing.T) {
	t.Setenv(config.EnvTokenName, "")
	useTokenStore(t, &failingTokenStore{})

	_, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	// Still ErrNoToken (exit code 77), with ErrTokenStore and the cause.
	if !errors.Is(err, ErrNoToken) || !errors.Is(err, ErrTokenStore) || !errors.Is(err, errVaultLocked) {
		t.Errorf("GetValidToken() error = %v, want ErrNoToken + ErrTokenStore + the store's error", err)
	}
}

// Without config.SetEnvLogin(true), RETYC_TOKEN is ignored: an importer with
// an empty store is not logged in, and no refresh is attempted.
func TestGetValidTokenIgnoresEnvWithoutOptIn(t *testing.T) {
	t.Setenv(config.EnvTokenName, "offline-token")
	config.SetEnvLogin(false)
	t.Cleanup(func() { config.SetEnvLogin(true) })
	useTokenStore(t, &memTokenStore{})

	_, err := GetValidToken(context.Background(), config.OIDCConfig{}, http.DefaultClient)
	if !errors.Is(err, ErrNoToken) {
		t.Errorf("GetValidToken() error = %v, want ErrNoToken (RETYC_TOKEN must be ignored)", err)
	}
}
