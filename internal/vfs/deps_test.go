package vfs

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strconv"
	"strings"
	"testing"
)

const modulePath = "github.com/retyc/retyc-cli"

// forbiddenAnywhere lists the packages vfs and its sub-packages must not
// reach, directly or through a dependency: the front ends (WebDAV, FUSE, cobra
// commands). An entry ending in "/" also matches every package below it.
var forbiddenAnywhere = []string{
	"golang.org/x/net/webdav",
	"github.com/hanwen/go-fuse/",
	"github.com/spf13/cobra",
	modulePath + "/cmd",
}

// forbiddenDirect lists the packages vfs and its sub-packages must not import
// themselves. net/http cannot be banned transitively: internal/metrics and
// internal/telemetry wrap the API transport, and Prometheus pulls it in. Nor
// can viper and internal/config: internal/api and internal/service, which vfs
// builds on, import them. vfs itself takes its settings through Options.
var forbiddenDirect = append([]string{
	"net/http",
	"github.com/spf13/viper",
	modulePath + "/internal/config",
}, forbiddenAnywhere...)

// forbidden reports whether pkg matches an entry of list.
func forbidden(pkg string, list []string) bool {
	for _, f := range list {
		if pkg == f || (strings.HasSuffix(f, "/") && strings.HasPrefix(pkg, f)) {
			return true
		}
	}

	return false
}

// buildIgnored reports whether file carries a "//go:build ignore" constraint:
// such a file is never part of the package.
func buildIgnored(file *ast.File) bool {
	for _, group := range file.Comments {
		if group.Pos() >= file.Package {
			break
		}
		for _, c := range group.List {
			if strings.TrimSpace(strings.TrimPrefix(c.Text, "//go:build")) == "ignore" &&
				strings.HasPrefix(c.Text, "//go:build") {
				return true
			}
		}
	}

	return false
}

// goTool returns the go command of the toolchain that built this test when it
// is there, else the one on the PATH; "" when there is none.
func goTool() string {
	name := "go"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	// The test runs where it was built, which is what makes the build's GOROOT
	// meaningful here: it names the toolchain the dependencies are listed for.
	if root := runtime.GOROOT(); root != "" { //nolint:staticcheck // SA1019: see above
		if tool := filepath.Join(root, "bin", name); isFile(tool) {
			return tool
		}
	}
	if tool, err := exec.LookPath("go"); err == nil {
		return tool
	}

	return ""
}

func isFile(name string) bool {
	info, err := os.Stat(name)

	return err == nil && info.Mode().IsRegular()
}

// TestDependencyRule enforces that vfs and its sub-packages (metastore,
// memstore, ...) stay independent of the protocol that serves them and of the
// CLI's configuration: settings arrive through Options, and a front end
// imports vfs, never the reverse.
//
// The direct imports are read from the syntax tree of every non-test file
// below this directory, whatever its build constraints, "//go:build ignore"
// files excepted. The transitive ones come from `go list -deps ./...`, for the
// dev and the prod build; without a go tool that half is skipped, except on CI
// (the CI environment variable), where it fails.
func TestDependencyRule(t *testing.T) {
	t.Run("direct", func(t *testing.T) {
		fset := token.NewFileSet()
		checked := map[string]int{} // files checked, by directory
		err := filepath.WalkDir(".", func(name string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
				return nil
			}
			file, err := parser.ParseFile(fset, name, nil, parser.ImportsOnly|parser.ParseComments)
			if err != nil {
				return err
			}
			if buildIgnored(file) {
				return nil
			}
			checked[filepath.Dir(name)]++
			for _, imp := range file.Imports {
				pkg, err := strconv.Unquote(imp.Path.Value)
				if err != nil {
					return err
				}
				if forbidden(pkg, forbiddenDirect) {
					t.Errorf("%s imports %s", fset.Position(imp.Pos()), pkg)
				}
			}

			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
		// The walk must have reached the sub-packages, not only this one.
		for _, dir := range []string{
			".", "metastore", filepath.Join("metastore", "memstore"), filepath.Join("metastore", "redisstore"),
		} {
			if checked[dir] == 0 {
				t.Errorf("no source file checked in %s", dir)
			}
		}
	})

	for _, tags := range []string{"", "prod"} {
		t.Run("transitive/tags="+tags, func(t *testing.T) {
			tool := goTool()
			if tool == "" {
				if os.Getenv("CI") != "" {
					t.Fatal("go tool not found")
				}
				t.Skip("go tool not found")
			}
			cmd := exec.Command(tool, "list", "-deps", "-tags", tags, "./...") // #nosec G204 -- fixed arguments
			out, err := cmd.Output()
			if err != nil {
				t.Fatalf("go list -deps: %v", err)
			}
			deps := strings.Fields(string(out))
			if len(deps) < 2 {
				t.Fatalf("go list -deps returned %d packages", len(deps))
			}
			for _, sub := range []string{"", "/metastore", "/metastore/memstore", "/metastore/redisstore"} {
				if !slices.Contains(deps, modulePath+"/internal/vfs"+sub) {
					t.Errorf("go list -deps did not cover internal/vfs%s", sub)
				}
			}
			for _, pkg := range deps {
				if forbidden(pkg, forbiddenAnywhere) {
					t.Errorf("vfs depends on %s", pkg)
				}
			}
		})
	}
}

// The rule must not be satisfied by a list that matches nothing.
func TestForbidden(t *testing.T) {
	anywhere := map[string]bool{
		"net/http":                             false, // direct only
		"github.com/spf13/viper":               false, // direct only
		modulePath + "/internal/config":        false, // direct only
		"golang.org/x/net/webdav":              true,
		"github.com/hanwen/go-fuse/v2/fs":      true,
		"github.com/spf13/cobra":               true,
		modulePath + "/cmd":                    true,
		modulePath + "/internal/telemetry":     false,
		"github.com/spf13/pflag":               false,
		"github.com/go-viper/mapstructure/v2":  false,
		modulePath + "/internal/configuration": false,
	}
	for pkg, want := range anywhere {
		if got := forbidden(pkg, forbiddenAnywhere); got != want {
			t.Errorf("forbidden(%q) anywhere = %v, want %v", pkg, got, want)
		}
	}
	for _, pkg := range []string{
		"net/http", "github.com/spf13/viper", modulePath + "/internal/config",
		"golang.org/x/net/webdav", "github.com/hanwen/go-fuse/v2/fs", "github.com/spf13/cobra", modulePath + "/cmd",
	} {
		if !forbidden(pkg, forbiddenDirect) {
			t.Errorf("%s is not forbidden as a direct import", pkg)
		}
	}
	if forbidden(modulePath+"/internal/service", forbiddenDirect) {
		t.Error("internal/service must be importable")
	}
}

// A file excluded from every build is not part of the package.
func TestBuildIgnored(t *testing.T) {
	cases := map[string]bool{
		"//go:build ignore\n\npackage x\n":           true,
		"// doc\n\n//go:build ignore\n\npackage x\n": true,
		"//go:build linux\n\npackage x\n":            false,
		"//go:build !ignore\n\npackage x\n":          false,
		"package x\n\n//go:build ignore\n":           false, // after the package clause: a plain comment
	}
	for src, want := range cases {
		file, err := parser.ParseFile(token.NewFileSet(), "x.go", src, parser.ImportsOnly|parser.ParseComments)
		if err != nil {
			t.Fatalf("%q: %v", src, err)
		}
		if got := buildIgnored(file); got != want {
			t.Errorf("buildIgnored(%q) = %v, want %v", src, got, want)
		}
	}
}
