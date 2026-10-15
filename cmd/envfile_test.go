package cmd

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/spf13/viper"
)

func writeTestEnvFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "retyc.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}

	return path
}

// End to end: --env-file is loaded before viper and before the accessors of
// config are asked, for an offline command too.
func TestEnvFile_FlagFeedsAccessorsViperAndConfigDir(t *testing.T) {
	isolateConfig(t)
	cfgDir := t.TempDir()
	path := writeTestEnvFile(t, "# secrets of the unit\n"+
		"RETYC_KEY_PASSPHRASE=\"correct horse\"\n"+
		"RETYC_TOKEN=offline-token\n"+
		"RETYC_API_BASE_URL=https://api.file.example\n"+
		"RETYC_CONFIG_DIR="+cfgDir+"\n")

	if err := run(context.Background(), []string{"--env-file", path, "config", "path"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}

	if got, err := config.RequireKeyPassphrase(); err != nil || got != "correct horse" {
		t.Errorf("RequireKeyPassphrase() = %q, %v, want the passphrase of the file", got, err)
	}
	if got := config.Token(); got != "offline-token" {
		t.Errorf("Token() = %q, want the token of the file", got)
	}
	if got := viper.GetString("api.base_url"); got != "https://api.file.example" {
		t.Errorf("api.base_url = %q, want the value of the file: the file must be loaded before viper", got)
	}
	if dir, err := config.ConfigDir(); err != nil || dir != cfgDir {
		t.Errorf("ConfigDir() = %q, %v, want %q from the file", dir, err, cfgDir)
	}
	if envFileLoaded == nil || envFileLoaded.Path != path || len(envFileLoaded.Applied) != 4 {
		t.Errorf("envFileLoaded = %+v, want %s with 4 variables applied", envFileLoaded, path)
	}
}

// RETYC_ENV_FILE designates the file when the flag does not; the real
// environment wins over what the file says.
func TestEnvFile_VariableAndEnvironmentPrecedence(t *testing.T) {
	isolateConfig(t)
	fromVar := writeTestEnvFile(t, "RETYC_KEY_PASSPHRASE=from-file\nRETYC_TOKEN=from-variable-file\n")
	fromFlag := writeTestEnvFile(t, "RETYC_TOKEN=from-flag-file\n")
	t.Setenv(config.EnvFileName, fromVar)
	t.Setenv(config.EnvKeyPassphraseName, "from-env")

	if err := run(context.Background(), []string{"config", "path"}); err != nil {
		t.Fatalf("run() error = %v", err)
	}
	if got := config.KeyPassphrase(); got != "from-env" {
		t.Errorf("KeyPassphrase() = %q, want the environment's", got)
	}
	if got := config.Token(); got != "from-variable-file" {
		t.Errorf("Token() = %q, want the file of RETYC_ENV_FILE", got)
	}

	if err := run(context.Background(), []string{"--env-file", fromFlag, "config", "path"}); err != nil {
		t.Fatalf("run(--env-file) error = %v", err)
	}
	if got := config.Token(); got != "from-flag-file" {
		t.Errorf("Token() = %q, want the file of the flag", got)
	}
	// The flag's file says nothing of the passphrase, and the first file is
	// no longer applied.
	if got := config.KeyPassphrase(); got != "from-env" {
		t.Errorf("KeyPassphrase() = %q, want the environment's", got)
	}
}

// A designated file that does not load stops a command with the
// configuration exit code, before anything else; an offline command still
// runs and reports it.
func TestEnvFile_UnloadableFileIsFatal(t *testing.T) {
	isolateConfig(t)
	t.Setenv(config.EnvConfigDirName, t.TempDir())
	missing := filepath.Join(t.TempDir(), "absent.env")

	err := run(context.Background(), []string{"--env-file", missing, "auth", "status"})
	if !errors.Is(err, config.ErrEnvFile) {
		t.Fatalf("run(auth status) error = %v, want config.ErrEnvFile", err)
	}
	if got := exitCode(err); got != exitConfig {
		t.Errorf("exitCode() = %d, want %d", got, exitConfig)
	}

	if err := run(context.Background(), []string{"--env-file", missing, "config", "path"}); err != nil {
		t.Errorf("run(config path) error = %v, want an offline command to run", err)
	}
	if envFileErr == nil {
		t.Error("envFileErr = nil, want the error config path reports")
	}

	if runtime.GOOS == "windows" {
		return // no mode bits to refuse
	}
	open := writeTestEnvFile(t, "RETYC_TOKEN=s3cr3t\n")
	if err := os.Chmod(open, 0o644); err != nil { //nolint:gosec // G302: the too-open mode under test
		t.Fatal(err)
	}
	err = run(context.Background(), []string{"--env-file", open, "auth", "status"})
	if !errors.Is(err, config.ErrEnvFile) {
		t.Fatalf("run(world-readable file) error = %v, want config.ErrEnvFile", err)
	}
	if config.Token() != "" {
		t.Error("a world-readable file was applied")
	}
}
