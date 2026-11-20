package auth

import "github.com/retyc/retyc-cli/pkg/config"

// The tests run with the store and the environment login of the CLI, as cmd
// sets them.
func init() {
	SetTokenStore(config.TokenFile{})
	config.SetEnvLogin(true)
}
