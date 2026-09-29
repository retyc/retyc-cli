package ui

import "testing"

func TestEscape(t *testing.T) {
	tests := []struct {
		name, in, want string
	}{
		{"plain", "rapport-2026.pdf", "rapport-2026.pdf"},
		{"unicode kept", "résumé été 日本.txt", "résumé été 日本.txt"},
		{"space and quotes kept", `mon "rapport" a\b.pdf`, `mon "rapport" a\b.pdf`},
		{
			"PoC 5 name",
			"facture.pdf\x1b[2K\rFILE  rapport-anodin.pdf\x1b]0;PWNED\x07",
			`"facture.pdf\x1b[2K\rFILE  rapport-anodin.pdf\x1b]0;PWNED\a"`,
		},
		{"newline and tab", "a\nb\tc", `"a\nb\tc"`},
		{"DEL", "a\x7fb", `"a\x7fb"`},
		{"C1 CSI encoded", "a\u009b31mb", `"a\u009b31mb"`},
		{"raw 0x9b byte", "a\x9b31mb", `"a\x9b31mb"`},
		{"bidi override", "invoice\u202Efdp.exe", `"invoice\u202efdp.exe"`},
		{"zero width space", "a\u200Bb", `"a\u200bb"`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Escape(tt.in); got != tt.want {
				t.Errorf("Escape(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestEscapeLines(t *testing.T) {
	in := "uploading x\x1b[2K: failed\nHint: retry"
	want := `"uploading x\x1b[2K: failed"` + "\nHint: retry"
	if got := EscapeLines(in); got != want {
		t.Errorf("EscapeLines(%q) = %q, want %q", in, got, want)
	}
}

func TestFileName(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"rapport.pdf", "rapport.pdf"},
		{"a\x1b[2K\rb\x07", "a_[2K_b_"},
		{"invoice\u202Efdp.exe", "invoice_fdp.exe"},
		{"a\x9bb", "a\uFFFDb"},
	}
	for _, tt := range tests {
		if got := FileName(tt.in); got != tt.want {
			t.Errorf("FileName(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
