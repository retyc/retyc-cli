package service

import (
	"github.com/retyc/retyc-cli/pkg/auth"
	"github.com/retyc/retyc-cli/pkg/config"
)

// The tests run with the token store and the environment login of the CLI,
// as cmd sets them.
func init() {
	auth.SetTokenStore(config.TokenFile{})
	config.SetEnvLogin(true)
}
