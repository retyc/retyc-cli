package cmd

import (
	"os"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/service"
)

// Under --json the documented contract is: result on stdout OR {"error":...}
// on stderr with an empty stdout — never both, and no plain-text error lines
// mixed into stderr.
func TestReportExportResult_JSONWithErrorsKeepsStdoutEmpty(t *testing.T) {
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	m := service.AdminExportManifest{
		Datarooms: 2, DataroomsExported: 1,
		DataroomsSkipped: []service.AdminExportSkipped{{ID: "dr-locked", Title: "Locked", Reason: "no access"}},
		Errors:           []string{"dataroom dr-x (X): boom"},
	}

	var err error
	var stderr string
	stdout := captureStream(t, &os.Stdout, func() {
		stderr = captureStream(t, &os.Stderr, func() {
			err = reportExportResult(m, "out")
		})
	})

	if err == nil {
		t.Fatal("expected an error when the manifest records errors")
	}
	if strings.TrimSpace(stdout) != "" {
		t.Errorf("stdout = %q, want empty on error under --json", stdout)
	}
	if strings.Contains(stderr, "ERROR:") {
		t.Errorf("stderr = %q, want no plain-text ERROR lines under --json", stderr)
	}
}

func TestReportExportResult_JSONWithoutErrorsPrintsManifest(t *testing.T) {
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	m := service.AdminExportManifest{Datarooms: 1, DataroomsExported: 1}

	var err error
	stdout := captureStream(t, &os.Stdout, func() {
		err = reportExportResult(m, "out")
	})
	if err != nil {
		t.Fatalf("reportExportResult() error = %v", err)
	}
	if !strings.Contains(stdout, `"datarooms_exported": 1`) {
		t.Errorf("stdout = %q, want the manifest JSON", stdout)
	}
}
