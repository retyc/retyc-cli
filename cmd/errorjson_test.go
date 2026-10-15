package cmd

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"

	"github.com/retyc/retyc-cli/internal/api"
	"github.com/retyc/retyc-cli/internal/auth"
	"github.com/retyc/retyc-cli/internal/config"
)

func TestErrorKind(t *testing.T) {
	refusal := func(status int, body string) error {
		return fmt.Errorf("doing it: %w", &api.HTTPError{Status: status, Body: body})
	}
	coded := func(status int, code, body string) error {
		return fmt.Errorf("doing it: %w", &api.HTTPError{Status: status, Code: code, Body: body})
	}
	detail := func(d string) string { return `{"detail":"` + d + `"}` }
	tooSmall := `{"detail":[{"loc":["body","storage_capacity"],` +
		`"msg":"Value error, Reserved storage capacity must be at least 21474836480 bytes","type":"value_error"}]}`
	cases := []struct {
		name string
		err  error
		want string
	}{
		{"no token", fmt.Errorf("x: %w", auth.ErrNoToken), kindAuthRequired},
		{"passphrase", config.ErrNoKeyPassphrase, kindConfig},
		{"lost writes", lostWritesError{errors.New("2 files lost")}, kindLostWrites},
		{"login and lost writes", errors.Join(auth.ErrNoRefreshToken, lostWritesError{errors.New("lost")}), kindAuthRequired},
		{"needs yes", errJSONNeedsYes, kindNeedsYes},
		{"rate limit", &api.RateLimitError{Last: &api.HTTPError{Status: 429}}, kindRateLimited},
		{"storage", refusal(400, detail("File size 9 exceeds maximum allowed storage size 8")), kindStorageExceeded},
		{"plan", refusal(400, detail("Not enough storage left on the owner's plan for this capacity")), kindPlanExceeded},
		{"too small", refusal(422, tooSmall), kindCapacityTooSmall},
		{"shrink", refusal(400, `{"detail":"A reservation can only be enlarged"}`), kindCapacityShrink},
		{"401", refusal(401, ``), kindUnauthenticated},
		{"403", refusal(403, `{"detail":"Add version not allowed"}`), kindForbidden},
		{"404", refusal(404, ``), kindNotFound},
		{"410", refusal(410, ``), kindGone},
		{"409", refusal(409, ``), kindConflict},
		{"423", refusal(423, ``), kindLocked},
		{"426", refusal(426, `{"detail":"Retyc CLI version could not be determined"}`), kindCLITooOld},
		{"other 400", refusal(400, `{"detail":"Maximum number of versions reached (5)"}`), kindInvalid},
		{"500", refusal(500, `oops`), kindAPIError},
		{"plain", errors.New("boom"), kindError},
		// The API with X-Error-Code: the code decides, whatever the detail.
		{"storage code", coded(400, api.CodeStorageExceeded, detail("Not enough storage")), kindStorageExceeded},
		{"plan code", coded(400, api.CodeStoragePlanExceeded, detail("Not enough room")), kindPlanExceeded},
		{"too small code", coded(400, api.CodeStorageCapacityTooSmall, detail("Too small")), kindCapacityTooSmall},
		{"shrink code", coded(400, api.CodeStorageCapacityShrink, detail("Only larger")), kindCapacityShrink},
		{"other code, former plan text", coded(400, api.CodeVersionsLimit,
			detail("Not enough storage left on the owner's plan")), kindInvalid},
		{"other code, former shrink text", coded(400, "DATAROOMS_LIMIT",
			detail("A reservation can only be enlarged")), kindInvalid},
		{"other code, former storage text", coded(400, api.CodeVersionsLimit,
			detail("File size 9 exceeds maximum allowed storage size 8")), kindInvalid},
		{"404 with code", coded(404, api.CodeDataroomNotFound, detail("Gone")), kindNotFound},
	}
	for _, c := range cases {
		if got := errorKind(c.err); got != c.want {
			t.Errorf("%s: errorKind = %q, want %q", c.name, got, c.want)
		}
	}
}

func TestPrintError_JSONCarriesStatusAndDetail(t *testing.T) {
	jsonOutput = true
	defer func() { jsonOutput = false }()

	err := fmt.Errorf("set: %w", &api.HTTPError{Status: 422, Body: `{"detail":[{"msg":"a"},{"msg":"b"}]}`})
	out := captureStream(t, &os.Stderr, func() { printError(err) })
	var got map[string]any
	if jErr := json.Unmarshal([]byte(out), &got); jErr != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", jErr, out)
	}
	if got["kind"] != kindInvalid || got["status"] != float64(422) || got["detail"] != "a; b" ||
		got["error"] != err.Error() {
		t.Errorf("unexpected payload: %v", got)
	}

	out = captureStream(t, &os.Stderr, func() { printError(errors.New("boom")) })
	got = nil
	if jErr := json.Unmarshal([]byte(out), &got); jErr != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", jErr, out)
	}
	if _, ok := got["status"]; ok || got["kind"] != kindError {
		t.Errorf("a local error carries no status, kind %q: %v", kindError, got)
	}
	if _, ok := got["detail"]; ok {
		t.Errorf("a local error carries no detail: %v", got)
	}
	if _, ok := got["code"]; ok {
		t.Errorf("a local error carries no code: %v", got)
	}
}

func TestPrintError_JSONCarriesCode(t *testing.T) {
	jsonOutput = true
	defer func() { jsonOutput = false }()

	err := fmt.Errorf("set: %w", &api.HTTPError{Status: 400, Code: api.CodeStorageCapacityShrink,
		Body: `{"detail":"A reserved capacity can only be enlarged"}`})
	out := captureStream(t, &os.Stderr, func() { printError(err) })
	var got map[string]any
	if jErr := json.Unmarshal([]byte(out), &got); jErr != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", jErr, out)
	}
	if got["code"] != api.CodeStorageCapacityShrink || got["kind"] != kindCapacityShrink || got["status"] != float64(400) {
		t.Errorf("unexpected payload: %v", got)
	}

	// A refusal without a code (an older API) has no code field.
	err = fmt.Errorf("set: %w", &api.HTTPError{Status: 404, Body: `{"detail":"Not Found"}`})
	out = captureStream(t, &os.Stderr, func() { printError(err) })
	got = nil
	if jErr := json.Unmarshal([]byte(out), &got); jErr != nil {
		t.Fatalf("stderr is not valid JSON: %v\n%s", jErr, out)
	}
	if _, ok := got["code"]; ok {
		t.Errorf("a refusal without X-Error-Code carries a code: %v", got)
	}
}

func TestAdminErrHint(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		hint string
	}{
		{"401", fmt.Errorf("x: %w", &api.HTTPError{Status: 401}), "invalid or revoked"},
		{"403", fmt.Errorf("x: %w", &api.HTTPError{Status: 403}), "admin org scopes"},
		{"404", fmt.Errorf("x: %w", &api.HTTPError{Status: 404}), ""},
		{"text only", errors.New("API error 403: forged"), ""},
	} {
		got := adminErrHint(tc.err)
		if !errors.Is(got, tc.err) {
			t.Errorf("%s: %v does not wrap the error", tc.name, got)
		}
		if has := strings.Contains(got.Error(), "Hint:"); has != (tc.hint != "") ||
			(tc.hint != "" && !strings.Contains(got.Error(), tc.hint)) {
			t.Errorf("%s: adminErrHint = %q, want hint %q", tc.name, got, tc.hint)
		}
	}
	if adminErrHint(nil) != nil {
		t.Error("adminErrHint(nil) != nil")
	}
}

func TestExitCode_LostWrites(t *testing.T) {
	if got := exitCode(fmt.Errorf("x: %w", lostWritesError{errors.New("lost")})); got != exitLostWrites {
		t.Errorf("exitCode = %d, want %d", got, exitLostWrites)
	}
}
