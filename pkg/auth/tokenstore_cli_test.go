package auth

import "github.com/retyc/retyc-cli/pkg/config"

// The tests run with the store of the CLI, as cmd sets it.
func init() { SetTokenStore(config.TokenFile{}) }
