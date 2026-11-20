package dav

import (
	"go/parser"
	"go/token"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/retyc/retyc-cli"

// TestDependencyRule keeps the adapter importable by another module: it never
// imports cobra, pflag, viper, pkg/config nor cmd itself, and never reaches
// cobra or cmd through a dependency. viper and pkg/config still come in
// through pkg/api and pkg/service, as for vfs.
func TestDependencyRule(t *testing.T) {
	direct := []string{
		"github.com/spf13/cobra", "github.com/spf13/pflag", "github.com/spf13/viper",
		modulePath + "/pkg/config", modulePath + "/cmd",
	}
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	for _, name := range files {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		for _, imp := range f.Imports {
			path, _ := strconv.Unquote(imp.Path.Value)
			for _, bad := range direct {
				if path == bad {
					t.Errorf("%s imports %s", name, path)
				}
			}
		}
	}

	goCmd := filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // SA1019: the toolchain that built the test
	if _, err := os.Stat(goCmd); err != nil {
		t.Skip("no go command to list the dependencies")
	}
	// Fixed arguments: nothing comes from outside the test.
	out, err := exec.CommandContext(t.Context(), goCmd, "list", "-deps", ".").Output() //nolint:gosec // G204
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	for dep := range strings.FieldsSeq(string(out)) {
		if dep == "github.com/spf13/cobra" || dep == modulePath+"/cmd" {
			t.Errorf("pkg/dav depends on %s", dep)
		}
	}
}
