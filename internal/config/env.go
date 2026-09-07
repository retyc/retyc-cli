package config

import (
	"errors"
	"os"
	"strings"
)

// Environment variables holding secrets or bootstrap information.
//
// They are deliberately kept out of viper. Routing them through AutomaticEnv
// would also make them settable from config.yaml — viper cannot tell the two
// sources apart — and these values must never be written to disk in clear
// text. RETYC_CONFIG_DIR has a second reason: it is read before viper is
// initialised, to locate the config file itself.
const (
	EnvTokenName          = "RETYC_TOKEN"
	EnvKeyPassphraseName  = "RETYC_KEY_PASSPHRASE"  //nolint:gosec // G101: variable name, not a credential
	EnvWebdavPasswordName = "RETYC_WEBDAV_PASSWORD" //nolint:gosec // G101: variable name, not a credential
	EnvConfigDirName      = "RETYC_CONFIG_DIR"
)

// ErrNoKeyPassphrase is returned when the key passphrase is required but the
// environment does not carry one and no interactive prompt is possible.
var ErrNoKeyPassphrase = errors.New(EnvKeyPassphraseName + " environment variable is required")

// mcpbPlaceholderPrefix starts an MCPB user_config placeholder. Older MCPB
// clients inject the literal "${user_config.<name>}" when an optional
// user_config value is left empty in the extension settings.
//
// The check is a prefix, not a substring: a passphrase is user-chosen text and
// may legitimately contain "${".
const mcpbPlaceholderPrefix = "${user_config."

// fromEnv reads name and treats an unsubstituted MCPB placeholder as unset.
func fromEnv(name string) string {
	v := os.Getenv(name)
	if strings.HasPrefix(v, mcpbPlaceholderPrefix) {
		return ""
	}

	return v
}

// Token returns the offline refresh token from RETYC_TOKEN, or "" when unset.
func Token() string {
	return fromEnv(EnvTokenName)
}

// KeyPassphrase returns the AGE key passphrase from RETYC_KEY_PASSPHRASE, or
// "" when unset. Callers that can fall back to an interactive prompt use this;
// callers that cannot use RequireKeyPassphrase.
func KeyPassphrase() string {
	return fromEnv(EnvKeyPassphraseName)
}

// RequireKeyPassphrase returns the AGE key passphrase, or ErrNoKeyPassphrase
// when it is unset. It is the single entry point for the non-interactive
// callers (MCP server, WebDAV server), which have no terminal to prompt on.
func RequireKeyPassphrase() (string, error) {
	if v := KeyPassphrase(); v != "" {
		return v, nil
	}

	return "", ErrNoKeyPassphrase
}

// WebdavPassword returns the WebDAV Basic auth password from
// RETYC_WEBDAV_PASSWORD, or "" when unset.
func WebdavPassword() string {
	return os.Getenv(EnvWebdavPasswordName)
}
