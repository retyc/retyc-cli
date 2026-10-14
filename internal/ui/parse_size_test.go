package ui

import (
	"strings"
	"testing"
)

func TestParseSize(t *testing.T) {
	cases := []struct {
		in   string
		want int64
	}{
		{"1048576", 1 << 20},
		{"512B", 512},
		{"10K", 10 << 10},
		{"10KiB", 10 << 10},
		{"50G", 50 << 30},
		{"50GiB", 50 << 30},
		{"50 gib", 50 << 30},
		{"1.5TiB", 3 << 39},
		{"2P", 2 << 50},
	}
	for _, c := range cases {
		got, err := ParseSize(c.in)
		if err != nil {
			t.Errorf("ParseSize(%q) error = %v", c.in, err)

			continue
		}
		if got != c.want {
			t.Errorf("ParseSize(%q) = %d, want %d", c.in, got, c.want)
		}
	}
}

func TestParseSizeRejects(t *testing.T) {
	for _, in := range []string{"", "0", "-1G", "G", "abc", "10X", "10GB", "1.5", "0.1B", "9000000PiB"} {
		if got, err := ParseSize(in); err == nil {
			t.Errorf("ParseSize(%q) = %d, want an error", in, got)
		}
	}
}

func TestParseSizeTooLarge(t *testing.T) {
	// A whole byte count beyond int64 is too large, not "not a whole number".
	for _, in := range []string{"9223372036854775808", "99999999999999999999G"} {
		_, err := ParseSize(in)
		if err == nil || !strings.Contains(err.Error(), "too large") {
			t.Errorf("ParseSize(%q) error = %v, want \"too large\"", in, err)
		}
	}
}
