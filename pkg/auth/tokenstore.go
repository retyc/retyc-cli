package auth

import (
	"errors"
	"fmt"
	"os"
	"sync"

	"golang.org/x/oauth2"
)

// TokenStore keeps the login token between runs. The CLI stores it in
// <configDir>/token.json (config.TokenFile); a program that imports the core
// gives its own store (an OS vault) to SetTokenStore.
type TokenStore interface {
	// Load returns the stored token, or an error that wraps os.ErrNotExist
	// when there is none.
	Load() (*oauth2.Token, error)
	// Save replaces the stored token.
	Save(tok *oauth2.Token) error
	// Delete removes the stored token; deleting none is no error.
	Delete() error
}

// ErrNoTokenStore is returned when a token is to be read or written and no
// store was set with SetTokenStore. Loading wraps os.ErrNotExist too, so it
// reads as "not logged in" (ErrNoToken).
var ErrNoTokenStore = errors.New("no token store configured")

var (
	tokenStoreMu sync.RWMutex
	tokenStore   TokenStore
)

// SetTokenStore sets the store GetValidToken, the refreshing token source and
// the login commands of the service package read and write the token
// through. There is none by default: the CLI sets config.TokenFile at
// startup, so that nothing is written in a directory the importer did not
// choose.
func SetTokenStore(s TokenStore) {
	tokenStoreMu.Lock()
	defer tokenStoreMu.Unlock()
	tokenStore = s
}

// Tokens returns the store set by SetTokenStore, or one that holds nothing
// and refuses writes (ErrNoTokenStore) when none was set.
func Tokens() TokenStore {
	tokenStoreMu.RLock()
	defer tokenStoreMu.RUnlock()
	if tokenStore == nil {
		return noTokenStore{}
	}

	return tokenStore
}

// noTokenStore is the store of a program that set none.
type noTokenStore struct{}

func (noTokenStore) Load() (*oauth2.Token, error) {
	return nil, fmt.Errorf("%w: %w", ErrNoTokenStore, os.ErrNotExist)
}

func (noTokenStore) Save(*oauth2.Token) error { return ErrNoTokenStore }

func (noTokenStore) Delete() error { return nil }
