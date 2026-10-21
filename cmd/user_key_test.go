package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/retyc/retyc-cli/internal/config"
	"github.com/retyc/retyc-cli/internal/crypto"
	"github.com/retyc/retyc-cli/internal/service"
)

func TestErrorKind_KeyRotationIncomplete(t *testing.T) {
	err := fmt.Errorf("%w: 2 error(s)", service.ErrKeyRotationIncomplete)
	if got := errorKind(err); got != kindKeyRotationIncomplete {
		t.Errorf("kind = %q, want %q", got, kindKeyRotationIncomplete)
	}
	if got := exitCode(err); got != 1 {
		t.Errorf("exit code = %d, want 1", got)
	}
}

func TestNewKeyRotationJSON_EmptyLists(t *testing.T) {
	b, err := json.Marshal(newKeyRotationJSON(&service.KeyRotationResult{KeyID: "k", PublicKey: "age1pq1x"}))
	if err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b, &got); err != nil {
		t.Fatal(err)
	}
	if l, ok := got["revoked"].([]any); !ok || len(l) != 0 {
		t.Errorf("revoked = %v, want []: %s", got["revoked"], b)
	}
	for _, k := range []string{"datarooms", "transfers"} {
		o, ok := got[k].(map[string]any)
		if !ok {
			t.Fatalf("%s missing: %s", k, b)
		}
		for _, l := range []string{"skipped", "failed"} {
			if v, ok := o[l].([]any); !ok || len(v) != 0 {
				t.Errorf("%s.%s = %v, want []: %s", k, l, o[l], b)
			}
		}
	}
	if _, ok := got["fingerprint"]; ok {
		t.Errorf("human view carries fingerprint: %s", b)
	}
}

func TestUserKeyRotate_NeedsYesWithJSON(t *testing.T) {
	isolateConfig(t)
	jsonOutput = true
	t.Cleanup(func() { jsonOutput = false })
	userKeyRotateCmd.SetContext(context.Background())
	if err := userKeyRotateCmd.RunE(userKeyRotateCmd, nil); !errors.Is(err, errJSONNeedsYes) {
		t.Fatalf("err = %v, want errJSONNeedsYes", err)
	}
}

func TestUserKeyRotate_MachineFinishesSwapBeforeLoad(t *testing.T) {
	f := setupMachineStatus(t, true)
	cur, err := config.MachineAgeKeyPath()
	if err != nil {
		t.Fatal(err)
	}
	// A swap interrupted between its two renames: age.key.old and
	// age.key.new, no age.key.
	if err := os.Rename(cur, cur+".new"); err != nil {
		t.Fatal(err)
	}
	old, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cur+".old", []byte(old.String()+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	userKeyRotateYes = true
	t.Cleanup(func() { userKeyRotateYes = false })
	userKeyRotateCmd.SetContext(context.Background())
	var runErr error
	captureStream(t, &os.Stderr, func() {
		captureStream(t, &os.Stdout, func() {
			runErr = userKeyRotateCmd.RunE(userKeyRotateCmd, nil)
		})
	})
	// The fake API knows nothing of the rotation: the command must fail on
	// the API, not on the machine configuration.
	if runErr == nil || errors.Is(runErr, config.ErrMachineConfig) || exitCode(runErr) == exitConfig {
		t.Fatalf("err = %v (exit %d), want an API failure", runErr, exitCode(runErr))
	}
	if f.calls.Load() == 0 {
		t.Error("the API was never reached")
	}
	if _, err := os.Stat(cur); err != nil {
		t.Errorf("age.key not restored: %v", err)
	}
}
