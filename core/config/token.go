package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/oauth2"
)

// TokenFileStore keeps the login token in a JSON file (mode 0600, its
// directory created 0700). It satisfies auth.TokenStore; the CLI's store
// (cliconfig.TokenFile) resolves token.json in the config directory and
// delegates here.
type TokenFileStore struct {
	Path string
}

// Load reads the token; a missing file wraps os.ErrNotExist.
func (s TokenFileStore) Load() (*oauth2.Token, error) {
	f, err := os.Open(s.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("no stored token found: %w", os.ErrNotExist)
		}

		return nil, err
	}
	defer f.Close() //nolint:errcheck

	var tok oauth2.Token
	if err := json.NewDecoder(f).Decode(&tok); err != nil {
		return nil, err
	}

	return &tok, nil
}

// Save replaces the token file.
func (s TokenFileStore) Save(tok *oauth2.Token) error {
	if err := os.MkdirAll(filepath.Dir(s.Path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(s.Path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	defer f.Close() //nolint:errcheck

	return json.NewEncoder(f).Encode(tok) //nolint:gosec // G117: token storage is intentional
}

// Delete removes the token file; a missing one is no error.
func (s TokenFileStore) Delete() error {
	if err := os.Remove(s.Path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}

	return nil
}
