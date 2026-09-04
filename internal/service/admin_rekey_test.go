package service

import (
	"context"
	"reflect"
	"testing"

	"github.com/retyc/retyc-cli/internal/crypto"
)

func TestRekeyRecipientKeys(t *testing.T) {
	tests := []struct {
		name        string
		holders     []rekeyKeyHolder
		wantKeys    []string
		wantSkipped []string
	}{
		{
			name: "expected key takes precedence over current",
			holders: []rekeyKeyHolder{
				{Label: "a@x.co", PublicKey: ptr("old"), ExpectedPublicKey: ptr("new")},
			},
			wantKeys: []string{"new"},
		},
		{
			name: "current key used when no expected key",
			holders: []rekeyKeyHolder{
				{Label: "b@x.co", PublicKey: ptr("cur")},
			},
			wantKeys: []string{"cur"},
		},
		{
			name: "keyless holder skipped",
			holders: []rekeyKeyHolder{
				{Label: "ext@x.co"},
				{Label: "c@x.co", PublicKey: ptr("k1")},
			},
			wantKeys:    []string{"k1"},
			wantSkipped: []string{"ext@x.co"},
		},
		{
			name: "duplicate keys deduplicated",
			holders: []rekeyKeyHolder{
				{Label: "a@x.co", PublicKey: ptr("k1")},
				{Label: "b@x.co", PublicKey: ptr("k1")},
			},
			wantKeys: []string{"k1"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			keys, skipped := rekeyRecipientKeys(tt.holders)
			if !reflect.DeepEqual(keys, tt.wantKeys) {
				t.Errorf("keys = %v, want %v", keys, tt.wantKeys)
			}
			if !reflect.DeepEqual(skipped, tt.wantSkipped) {
				t.Errorf("skipped = %v, want %v", skipped, tt.wantSkipped)
			}
		})
	}
}

func TestPushRekey_AlwaysIncludesOrganizationKey(t *testing.T) {
	orgKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	member, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	// The service account is listed without any key (e.g. after a rotation):
	// the pushed blob must still be decryptable by the organization key.
	holders := []rekeyKeyHolder{
		{Label: "member@x.co", PublicKey: ptr(member.Recipient().String())},
		{Label: "service-account@x.co"},
	}

	var pushed string
	res, err := pushRekey(context.Background(), "SESSION-PRIVATE-KEY", orgKey, holders, func(blob string) error {
		pushed = blob

		return nil
	})
	if err != nil {
		t.Fatalf("pushRekey() error = %v", err)
	}
	if res.Reencrypted != 2 {
		t.Errorf("Reencrypted = %d, want 2 (member + organization key)", res.Reencrypted)
	}

	got, err := crypto.DecryptToString(pushed, orgKey)
	if err != nil {
		t.Fatalf("organization key cannot open the rekeyed blob: %v", err)
	}
	if got != "SESSION-PRIVATE-KEY" {
		t.Errorf("decrypted = %q, want session private key", got)
	}
	if _, err := crypto.DecryptToString(pushed, member); err != nil {
		t.Fatalf("member cannot open the rekeyed blob: %v", err)
	}
}

func TestPushRekey_OrganizationKeyNotDuplicated(t *testing.T) {
	orgKey, err := crypto.GenerateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	holders := []rekeyKeyHolder{
		{Label: "service-account@x.co", PublicKey: ptr(orgKey.Recipient().String())},
	}
	res, err := pushRekey(context.Background(), "k", orgKey, holders, func(string) error { return nil })
	if err != nil {
		t.Fatalf("pushRekey() error = %v", err)
	}
	if res.Reencrypted != 1 {
		t.Errorf("Reencrypted = %d, want 1", res.Reencrypted)
	}
}
