package cryptotest

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
)

const modulePath = "github.com/retyc/retyc-cli"

// testOnly lists the helper packages that must never be imported by a non-test
// file: cryptotest would ship a weak scrypt, telemetrytest an in-memory tracer.
var testOnly = []string{
	modulePath + "/internal/crypto/cryptotest",
	modulePath + "/internal/telemetry/telemetrytest",
}

// TestImportedByTestsOnly fails when a non-test file of the module imports a
// test-only helper. `go list` reports Imports without the test files, for the
// dev and the prod build; the helpers themselves are skipped.
func TestImportedByTestsOnly(t *testing.T) {
	// The toolchain that built this test, else the one on the PATH.
	goCmd := filepath.Join(runtime.GOROOT(), "bin", "go") //nolint:staticcheck // SA1019
	if _, err := os.Stat(goCmd); err != nil {
		goCmd = "go"
	}
	if _, err := exec.LookPath(goCmd); err != nil {
		if os.Getenv("CI") != "" {
			t.Fatalf("go command not found: %v", err)
		}
		t.Skipf("go command not found: %v", err)
	}

	for _, tags := range []string{"", "prod"} {
		out, err := exec.CommandContext(t.Context(), goCmd, "list", "-tags", tags, //nolint:gosec // fixed arguments
			"-f", "{{.ImportPath}}{{range .Imports}} {{.}}{{end}}", modulePath+"/...").Output()
		if err != nil {
			t.Fatalf("go list -tags %q: %v", tags, err)
		}
		for line := range strings.Lines(string(out)) {
			fields := strings.Fields(line)
			if len(fields) == 0 || slices.Contains(testOnly, fields[0]) {
				continue
			}
			for _, imp := range fields[1:] {
				if slices.Contains(testOnly, imp) {
					t.Errorf("%s imports %s outside a _test.go file (tags %q)", fields[0], imp, tags)
				}
			}
		}
	}
}
