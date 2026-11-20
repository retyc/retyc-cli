package service

import (
	"github.com/retyc/retyc-cli/pkg/auth"
	"github.com/retyc/retyc-cli/pkg/config"
)

// The tests run with the token store of the CLI, as cmd sets it.
func init() { auth.SetTokenStore(config.TokenFile{}) }
