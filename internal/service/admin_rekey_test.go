package service

import (
	"reflect"
	"testing"
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
