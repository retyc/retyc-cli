package auth

import (
	"path/filepath"

	"golang.org/x/oauth2"

	"github.com/retyc/retyc-cli/core/config"
)

// testTokenFile stands for the CLI's store (cliconfig.TokenFile), which the
// core cannot import: token.json in RETYC_CONFIG_DIR (the tests set it), else
// in .retyc, resolved at each call.
type testTokenFile struct{}

func (testTokenFile) file() config.TokenFileStore {
	dir := config.DirOverride()
	if dir == "" {
		dir = ".retyc"
	}

	return config.TokenFileStore{Path: filepath.Join(dir, "token.json")}
}

func (s testTokenFile) Load() (*oauth2.Token, error) { return s.file().Load() }
func (s testTokenFile) Save(tok *oauth2.Token) error { return s.file().Save(tok) }
func (s testTokenFile) Delete() error                { return s.file().Delete() }

// The tests run with a token store and the environment login of the CLI, as
// cmd sets them.
func init() {
	SetTokenStore(testTokenFile{})
	config.SetEnvLogin(true)
}
