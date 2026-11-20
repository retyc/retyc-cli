package config

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/spf13/viper"
)

// writeEnvFile writes content to a new file of the given mode.
func writeEnvFile(t *testing.T, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "retyc.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("WriteFile() error = %v", err)
	}
	if err := os.Chmod(path, mode); err != nil {
		t.Fatalf("Chmod() error = %v", err)
	}

	return path
}

// isolateEnvFile clears the inherited RETYC_ variables and takes back what a
// test's environment file injected.
func isolateEnvFile(t *testing.T) {
	t.Helper()
	resetViper(t)
	UnloadEnvFile()
	t.Cleanup(UnloadEnvFile)
}

func TestParseEnvFile(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string]string
		wantErr string // substring; "" for a file that parses
	}{
		{
			name:    "empty",
			content: "",
			want:    map[string]string{},
		},
		{
			name:    "comments and blank lines",
			content: "# a comment\n\n   \n  # another\n",
			want:    map[string]string{},
		},
		{
			name:    "plain",
			content: "RETYC_TOKEN=abc\n",
			want:    map[string]string{"RETYC_TOKEN": "abc"},
		},
		{
			name:    "no final newline",
			content: "RETYC_TOKEN=abc",
			want:    map[string]string{"RETYC_TOKEN": "abc"},
		},
		{
			name:    "export",
			content: "export RETYC_TOKEN=abc\nexport\tRETYC_API_BASE_URL=https://x\n",
			want:    map[string]string{"RETYC_TOKEN": "abc", "RETYC_API_BASE_URL": "https://x"},
		},
		{
			name:    "empty value",
			content: "RETYC_TOKEN=\n",
			want:    map[string]string{"RETYC_TOKEN": ""},
		},
		{
			name:    "value keeps equals and hash",
			content: "RETYC_TOKEN=a=b #c\n",
			want:    map[string]string{"RETYC_TOKEN": "a=b #c"},
		},
		{
			name:    "surrounding blanks trimmed",
			content: "  RETYC_TOKEN=  abc  \n",
			want:    map[string]string{"RETYC_TOKEN": "abc"},
		},
		{
			name:    "double quotes",
			content: `RETYC_TOKEN="  two words  "` + "\n",
			want:    map[string]string{"RETYC_TOKEN": "  two words  "}, //nolint:gosec // G101: fixture, not a credential
		},
		{
			name:    "single quotes",
			content: `RETYC_TOKEN='it "is" $HOME \n'` + "\n",
			want:    map[string]string{"RETYC_TOKEN": `it "is" $HOME \n`}, //nolint:gosec // G101: fixture, not a credential
		},
		{
			name:    "escapes in double quotes",
			content: `RETYC_TOKEN="a\"b\\c\nd'e"` + "\n",
			want:    map[string]string{"RETYC_TOKEN": `a"b\c\nd'e`}, //nolint:gosec // G101: fixture, not a credential
		},
		{
			name:    "no expansion",
			content: "RETYC_TOKEN=$HOME${USER}\n",
			want:    map[string]string{"RETYC_TOKEN": "$HOME${USER}"}, //nolint:gosec // G101: fixture, not a credential
		},
		{
			name:    "comment after quotes",
			content: `RETYC_TOKEN="abc" # the token` + "\n",
			want:    map[string]string{"RETYC_TOKEN": "abc"},
		},
		{
			name:    "quote inside a bare value",
			content: "RETYC_TOKEN=a'b\"c\n",
			want:    map[string]string{"RETYC_TOKEN": "a'b\"c"},
		},
		{
			name:    "CRLF and BOM",
			content: "\xef\xbb\xbfRETYC_TOKEN=abc\r\nRETYC_CONFIG_DIR=\"p\"\r\n",
			want:    map[string]string{"RETYC_TOKEN": "abc", "RETYC_CONFIG_DIR": "p"},
		},
		{
			name:    "last assignment wins",
			content: "RETYC_TOKEN=one\nRETYC_TOKEN=two\n",
			want:    map[string]string{"RETYC_TOKEN": "two"},
		},

		{
			name:    "foreign key",
			content: "RETYC_TOKEN=abc\nHTTPS_PROXY=http://s3cr3t@proxy\n",
			wantErr: "line 2: only RETYC_* variables",
		},
		{
			name:    "prefix alone is not enough",
			content: "RETYCX=s3cr3t\n",
			wantErr: "line 1: only RETYC_* variables",
		},
		{
			name:    "no equals",
			content: "\n\ns3cr3t\n",
			wantErr: "line 3: expected RETYC_NAME=value",
		},
		{
			name:    "blank before equals",
			content: "RETYC_TOKEN = s3cr3t\n",
			wantErr: "line 1: expected RETYC_NAME=value",
		},
		{
			name:    "empty name",
			content: "=s3cr3t\n",
			wantErr: "line 1: expected RETYC_NAME=value",
		},
		{
			name:    "name starting with a digit",
			content: "1RETYC_TOKEN=s3cr3t\n",
			wantErr: "line 1: expected RETYC_NAME=value",
		},
		{
			name:    "unterminated double quote",
			content: `RETYC_TOKEN="s3cr3t` + "\n",
			wantErr: "line 1: missing closing quote",
		},
		{
			name:    "unterminated single quote",
			content: "RETYC_TOKEN='s3cr3t\n",
			wantErr: "line 1: missing closing quote",
		},
		{
			name:    "text after the closing quote",
			content: `RETYC_TOKEN="s3cr3t" s3cr3t` + "\n",
			wantErr: "line 1: unexpected text after the closing quote",
		},
		{
			name:    "NUL byte",
			content: "RETYC_TOKEN=s3cr3t\x00\n",
			wantErr: "line 1: value holds a NUL byte",
		},
		{
			name:    "the file cannot designate a file",
			content: "RETYC_ENV_FILE=/s3cr3t\n",
			wantErr: "line 1: RETYC_ENV_FILE cannot be set",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			vars, err := parseEnvFile(tt.content)
			if tt.wantErr != "" {
				if err == nil {
					t.Fatalf("parseEnvFile() = %d variables, want an error containing %q", len(vars), tt.wantErr)
				}
				if !strings.Contains(err.Error(), tt.wantErr) {
					t.Errorf("error = %q, want it to contain %q", err, tt.wantErr)
				}
				// Every failing case writes its value as s3cr3t.
				if strings.Contains(err.Error(), "s3cr3t") {
					t.Errorf("error = %q quotes the line", err)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseEnvFile() error = %v", err)
			}
			got := map[string]string{}
			for _, v := range vars {
				got[v.name] = v.value
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("parseEnvFile() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLoadEnvFile_NoneDesignated(t *testing.T) {
	isolateEnvFile(t)

	loaded, err := LoadEnvFile("")
	if loaded != nil || err != nil {
		t.Errorf("LoadEnvFile(\"\") = %v, %v, want nil, nil", loaded, err)
	}
}

// The variables of the file reach the accessors and viper, exactly as if the
// process had inherited them.
func TestLoadEnvFile_AppliesToAccessorsAndViper(t *testing.T) {
	isolateEnvFile(t)
	path := writeEnvFile(t, "RETYC_KEY_PASSPHRASE='correct horse'\nexport RETYC_TOKEN=offline\n"+
		"RETYC_API_BASE_URL=https://api.file.example\n", 0o600)

	loaded, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile() error = %v", err)
	}
	want := []string{"RETYC_API_BASE_URL", "RETYC_KEY_PASSPHRASE", "RETYC_TOKEN"}
	if loaded.Path != path || !reflect.DeepEqual(loaded.Applied, want) || len(loaded.Kept) != 0 {
		t.Errorf("LoadEnvFile() = %+v, want path %s, applied %v, nothing kept", loaded, path, want)
	}

	if got := KeyPassphrase(); got != "correct horse" {
		t.Errorf("KeyPassphrase() = %q, want the value of the file", got)
	}
	if got := Token(); got != "offline" {
		t.Errorf("Token() = %q, want the value of the file", got)
	}
	SetDefaults()
	if got := viper.GetString("api.base_url"); got != "https://api.file.example" {
		t.Errorf("api.base_url = %q, want the value of the file", got)
	}

	UnloadEnvFile()
	if _, present := os.LookupEnv(EnvKeyPassphraseName); present {
		t.Error("UnloadEnvFile() left RETYC_KEY_PASSPHRASE in the environment")
	}
}

// The real environment wins over the file, an empty variable included.
func TestLoadEnvFile_EnvironmentWins(t *testing.T) {
	isolateEnvFile(t)
	t.Setenv(EnvKeyPassphraseName, "from-env")
	t.Setenv(EnvWebdavPasswordName, "")
	path := writeEnvFile(t,
		"RETYC_KEY_PASSPHRASE=from-file\nRETYC_WEBDAV_PASSWORD=from-file\nRETYC_TOKEN=from-file\n", 0o600)

	loaded, err := LoadEnvFile(path)
	if err != nil {
		t.Fatalf("LoadEnvFile() error = %v", err)
	}
	if got := KeyPassphrase(); got != "from-env" {
		t.Errorf("KeyPassphrase() = %q, want the environment's", got)
	}
	if got := WebdavPassword(); got != "" {
		t.Errorf("WebdavPassword() = %q, want the environment's empty value", got)
	}
	if got := Token(); got != "from-file" {
		t.Errorf("Token() = %q, want the file's", got)
	}
	if want := []string{"RETYC_KEY_PASSPHRASE", "RETYC_WEBDAV_PASSWORD"}; !reflect.DeepEqual(loaded.Kept, want) {
		t.Errorf("Kept = %v, want %v", loaded.Kept, want)
	}

	// Unloading takes back what the file set, never what the environment held.
	UnloadEnvFile()
	if got := KeyPassphrase(); got != "from-env" {
		t.Errorf("after UnloadEnvFile, KeyPassphrase() = %q, want the environment's", got)
	}
}

// The flag wins over RETYC_ENV_FILE, which applies when no flag is given.
func TestLoadEnvFile_FlagWinsOverVariable(t *testing.T) {
	isolateEnvFile(t)
	fromFlag := writeEnvFile(t, "RETYC_TOKEN=flag\n", 0o600)
	fromVar := writeEnvFile(t, "RETYC_TOKEN=variable\n", 0o600)
	t.Setenv(EnvFileName, fromVar)

	loaded, err := LoadEnvFile(fromFlag)
	if err != nil {
		t.Fatalf("LoadEnvFile(flag) error = %v", err)
	}
	if loaded.Path != fromFlag || Token() != "flag" {
		t.Errorf("path = %s, Token() = %q, want the file of the flag", loaded.Path, Token())
	}

	// A second load starts from the real environment: the first file's
	// variables are not taken for inherited ones.
	loaded, err = LoadEnvFile("")
	if err != nil {
		t.Fatalf("LoadEnvFile(\"\") error = %v", err)
	}
	if loaded.Path != fromVar || Token() != "variable" {
		t.Errorf("path = %s, Token() = %q, want the file of RETYC_ENV_FILE", loaded.Path, Token())
	}
}

func TestLoadEnvFile_Permissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("no mode bits on Windows")
	}
	for _, mode := range []os.FileMode{0o640, 0o604, 0o660, 0o644, 0o610, 0o601} {
		isolateEnvFile(t)
		path := writeEnvFile(t, "RETYC_TOKEN=s3cr3t\n", mode)

		_, err := LoadEnvFile(path)
		if !errors.Is(err, ErrEnvFile) {
			t.Fatalf("mode %#o: error = %v, want ErrEnvFile", mode, err)
		}
		if !strings.Contains(err.Error(), "chmod 600 "+path) {
			t.Errorf("mode %#o: error = %q, want it to say chmod 600", mode, err)
		}
		if Token() != "" {
			t.Errorf("mode %#o: the refused file was applied", mode)
		}
	}

	for _, mode := range []os.FileMode{0o600, 0o400} {
		isolateEnvFile(t)
		if _, err := LoadEnvFile(writeEnvFile(t, "RETYC_TOKEN=ok\n", mode)); err != nil {
			t.Errorf("mode %#o: error = %v, want none", mode, err)
		}
	}
}

func TestLoadEnvFile_Failures(t *testing.T) {
	isolateEnvFile(t)
	dir := t.TempDir()

	_, err := LoadEnvFile(filepath.Join(dir, "absent.env"))
	if !errors.Is(err, ErrEnvFile) || !errors.Is(err, os.ErrNotExist) {
		t.Errorf("missing file: error = %v, want ErrEnvFile wrapping os.ErrNotExist", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil { //nolint:gosec // G302: a directory, and the mode under test
			t.Fatal(err)
		}
		if _, err := LoadEnvFile(dir); !errors.Is(err, ErrEnvFile) {
			t.Errorf("directory: error = %v, want ErrEnvFile", err)
		}
	}

	// A malformed file applies nothing, not even the lines before the error.
	path := writeEnvFile(t, "RETYC_TOKEN=s3cr3t\nPATH=/s3cr3t\n", 0o600)
	_, err = LoadEnvFile(path)
	if !errors.Is(err, ErrEnvFile) || !strings.Contains(err.Error(), path+": line 2:") {
		t.Errorf("malformed file: error = %v, want ErrEnvFile naming the file and line 2", err)
	}
	if err != nil && strings.Contains(err.Error(), "s3cr3t") {
		t.Errorf("error = %q quotes a value", err)
	}
	if Token() != "" {
		t.Error("a malformed file was partly applied")
	}
}
