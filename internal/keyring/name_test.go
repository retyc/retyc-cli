package keyring

import (
	"errors"
	"strings"
	"testing"
)

func TestKeyName(t *testing.T) {
	got, err := keyName("d1a97a43-392b-4b16-b3fc-0842d8ad149b")
	if err != nil || got != "retyc:identity:d1a97a43-392b-4b16-b3fc-0842d8ad149b" {
		t.Fatalf("keyName(uuid) = %q, %v", got, err)
	}
	long := strings.Repeat("a", 64)
	if _, err := keyName(long); err != nil {
		t.Errorf("keyName(64 chars) error = %v, want nil", err)
	}
	for _, bad := range []string{"", "a;b", "a:b", "a b", "../x", string(make([]byte, 65))} {
		if _, err := keyName(bad); !errors.Is(err, ErrBadKeyID) {
			t.Errorf("keyName(%q) error = %v, want ErrBadKeyID", bad, err)
		}
	}
}
