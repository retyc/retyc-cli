package ui

import (
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Names, titles and messages are chosen by other users (or by the server)
// and decrypted client-side: they may carry terminal escape sequences that
// rewrite previous output lines, hide part of a listing or set the terminal
// title, or bidirectional formatting characters that visually reorder a name
// ("Trojan Source" spoofing). A rune is safe when unicode.IsGraphic accepts
// it: this rejects C0/C1 controls, DEL and every format character (Cf: bidi
// overrides and isolates, zero-width characters), and invalid UTF-8.

// Escape makes s safe to print on a terminal. A safe string is returned
// unchanged; any other is returned quoted by strconv.QuoteToGraphic, so the
// escaping is visible ("a\x1b[2K") rather than silent, the way GNU ls quotes
// file names it cannot print.
func Escape(s string) string {
	if isGraphic(s) {
		return s
	}

	return strconv.QuoteToGraphic(s)
}

// EscapeLines is Escape for multi-line text: line breaks are kept, each line
// is escaped. Used for error messages, which legitimately span several lines.
func EscapeLines(s string) string {
	lines := strings.Split(s, "\n")
	for i, l := range lines {
		lines[i] = Escape(l)
	}

	return strings.Join(lines, "\n")
}

// FileName replaces every non-graphic rune of name with "_", for use as an
// on-disk file name. Unlike Escape, it adds no quote and no backslash, which
// is a path separator on Windows. Invalid UTF-8 becomes U+FFFD.
func FileName(name string) string {
	return strings.Map(func(r rune) rune {
		if !unicode.IsGraphic(r) {
			return '_'
		}

		return r
	}, name)
}

// isGraphic reports whether s is valid UTF-8 made of graphic runes only.
func isGraphic(s string) bool {
	for _, r := range s {
		// Ranging over invalid UTF-8 yields utf8.RuneError, which is graphic:
		// check validity separately.
		if !unicode.IsGraphic(r) {
			return false
		}
	}

	return utf8.ValidString(s)
}
