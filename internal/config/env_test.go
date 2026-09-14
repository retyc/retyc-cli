package config

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// TestToken verifies that an unsubstituted MCPB user_config placeholder
// (injected by older MCPB clients when the optional token is left empty) is
// treated as unset, while a value that merely contains "${" is kept.
func TestToken(t *testing.T) {
	cases := []struct {
		name, value, want string
	}{
		{"unset", "", ""},
		{"real token", "abc123", "abc123"},
		{"mcpb placeholder", "${user_config.token}", ""},
		{"contains a brace but is not a placeholder", "x${y}", "x${y}"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv(EnvTokenName, tc.value)
			if got := Token(); got != tc.want {
				t.Errorf("Token() = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestKeyPassphrase_PlaceholderTreatedAsUnset(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "${user_config.key_passphrase}")
	if got := KeyPassphrase(); got != "" {
		t.Errorf("KeyPassphrase() = %q, want \"\"", got)
	}
}

// A passphrase is user-chosen text: "${" in it must not be mistaken for an
// MCPB placeholder.
func TestKeyPassphrase_KeepsDollarBrace(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "a${b}c")
	if got := KeyPassphrase(); got != "a${b}c" {
		t.Errorf("KeyPassphrase() = %q, want %q", got, "a${b}c")
	}
}

func TestRequireKeyPassphrase(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "s3cret")
	got, err := RequireKeyPassphrase()
	if err != nil {
		t.Fatalf("RequireKeyPassphrase() error = %v", err)
	}
	if got != "s3cret" {
		t.Errorf("RequireKeyPassphrase() = %q, want %q", got, "s3cret")
	}
}

func TestRequireKeyPassphrase_Unset(t *testing.T) {
	t.Setenv(EnvKeyPassphraseName, "")
	_, err := RequireKeyPassphrase()
	if !errors.Is(err, ErrNoKeyPassphrase) {
		t.Errorf("error = %v, want ErrNoKeyPassphrase", err)
	}
}

func TestWebdavPassword(t *testing.T) {
	t.Setenv(EnvWebdavPasswordName, "hunter2")
	if got := WebdavPassword(); got != "hunter2" {
		t.Errorf("WebdavPassword() = %q, want %q", got, "hunter2")
	}
}

// retycStringConsts returns, for a parsed file, the string constants whose
// value starts with RETYC_, keyed by constant name.
func retycStringConsts(file *ast.File) map[string]string {
	consts := map[string]string{}
	ast.Inspect(file, func(n ast.Node) bool {
		decl, ok := n.(*ast.GenDecl)
		if !ok || decl.Tok != token.CONST {
			return true
		}
		for _, spec := range decl.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					break
				}
				if v, ok := retycLiteral(vs.Values[i]); ok {
					consts[name.Name] = v
				}
			}
		}

		return true
	})

	return consts
}

// retycLiteral returns the value of expr when it is a string literal starting
// with RETYC_.
func retycLiteral(expr ast.Expr) (string, bool) {
	lit, ok := expr.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil || !strings.HasPrefix(v, "RETYC_") {
		return "", false
	}

	return v, true
}

// declaredEnvNames returns every RETYC_ variable name declared as a constant in
// env.go. TestEnvVarsDocumented derives its list from here, so declaring a new
// constant is enough to put it under the documentation check.
func declaredEnvNames(t *testing.T) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "env.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parsing env.go: %v", err)
	}
	names := make([]string, 0, 8)
	for _, v := range retycStringConsts(file) {
		names = append(names, v)
	}
	sort.Strings(names)

	return names
}

func TestDeclaredEnvNames(t *testing.T) {
	got := strings.Join(declaredEnvNames(t), " ")
	for _, want := range []string{
		EnvTokenName, EnvKeyPassphraseName, EnvWebdavPasswordName, EnvConfigDirName,
	} {
		if !strings.Contains(got, want) {
			t.Errorf("declaredEnvNames() = %q, missing %s", got, want)
		}
	}
}

// TestRetycEnvReadOnlyHere enforces that every RETYC_ environment variable is
// read in this package. A direct read elsewhere escapes TestEnvVarsDocumented,
// which only knows the names declared in env.go, so the variable silently ends
// up undocumented.
//
// It inspects the syntax tree, so comments and strings never trigger it. It
// flags os.Getenv / os.LookupEnv called with a RETYC_ string literal, or with a
// constant holding one that is declared in the same file. A name built at run
// time, declared in another file, or read through an aliased os import or
// os.Environ is out of its reach.
func TestRetycEnvReadOnlyHere(t *testing.T) {
	root := filepath.Join("..", "..")
	self, err := filepath.Abs(".")
	if err != nil {
		t.Fatalf("resolving package dir: %v", err)
	}

	fset := token.NewFileSet()
	var offenders []string
	err = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "vendor", "dist", "docs":
				return filepath.SkipDir
			}
			if abs, absErr := filepath.Abs(path); absErr == nil && abs == self {
				return filepath.SkipDir
			}

			return nil
		}
		if filepath.Ext(path) != ".go" {
			return nil
		}
		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		consts := retycStringConsts(file)
		ast.Inspect(file, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok || len(call.Args) == 0 {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || (sel.Sel.Name != "Getenv" && sel.Sel.Name != "LookupEnv") {
				return true
			}
			if pkg, ok := sel.X.(*ast.Ident); !ok || pkg.Name != "os" {
				return true
			}
			_, literal := retycLiteral(call.Args[0])
			ident, isIdent := call.Args[0].(*ast.Ident)
			if literal || (isIdent && consts[ident.Name] != "") {
				offenders = append(offenders, fset.Position(call.Pos()).String())
			}

			return true
		})

		return nil
	})
	if err != nil {
		t.Fatalf("walking the module: %v", err)
	}

	if len(offenders) > 0 {
		t.Errorf("RETYC_ variables must be read through internal/config/env.go, found direct reads at: %v",
			offenders)
	}
}
