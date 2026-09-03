package cmd

import (
	"encoding/json"
	"errors"
	"io"
	"os"
	"strings"
	"testing"
)

// captureStream redirects *stream (os.Stdout or os.Stderr) while fn runs and
// returns what was written.
func captureStream(t *testing.T, stream **os.File, fn func()) string {
	t.Helper()
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	orig := *stream
	*stream = w
	defer func() { *stream = orig }()

	fn()
	_ = w.Close()
	b, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read: %v", err)
	}

	return string(b)
}

func TestPrintJSON_IndentedOnStdout(t *testing.T) {
	out := captureStream(t, &os.Stdout, func() {
		if err := printJSON(idStatusJSON{ID: "abc", Status: "disabled"}); err != nil {
			t.Errorf("printJSON: %v", err)
		}
	})
	var got idStatusJSON
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\n%s", err, out)
	}
	if got.ID != "abc" || got.Status != "disabled" {
		t.Errorf("unexpected payload: %+v", got)
	}
	if !strings.Contains(out, "\n  \"id\"") {
		t.Errorf("expected indented output, got %q", out)
	}
}

func TestPrintError_JSONOnStderrWhenFlagSet(t *testing.T) {
	jsonOutput = true
	defer func() { jsonOutput = false }()

	out := captureStream(t, &os.Stderr, func() { printError(errors.New("boom \"quoted\"")) })
	var got struct {
		Error string `json:"error"`
	}
	if err := json.Unmarshal([]byte(out), &got); err != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", err, out)
	}
	if got.Error != `boom "quoted"` {
		t.Errorf("unexpected error payload: %q", got.Error)
	}
}

func TestPrintError_PlainTextByDefault(t *testing.T) {
	out := captureStream(t, &os.Stderr, func() { printError(errors.New("boom")) })
	if out != "boom\n" {
		t.Errorf("expected plain text, got %q", out)
	}
}

func TestConfirm_YesSkipsPrompt(t *testing.T) {
	ok, err := confirm("Delete?", true)
	if err != nil || !ok {
		t.Errorf("confirm(yes) = (%v, %v), want (true, nil)", ok, err)
	}
}

func TestConfirm_JSONWithoutYesFails(t *testing.T) {
	jsonOutput = true
	defer func() { jsonOutput = false }()

	ok, err := confirm("Delete?", false)
	if ok || !errors.Is(err, errJSONNeedsYes) {
		t.Errorf("confirm(--json, no --yes) = (%v, %v), want (false, errJSONNeedsYes)", ok, err)
	}
}

func TestNewPagedJSON_NilItemsBecomeEmptyArray(t *testing.T) {
	b, err := json.Marshal(newPagedJSON[string](nil, 0, 1, 1))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"items":[]`) {
		t.Errorf("expected empty array, got %s", b)
	}
}
