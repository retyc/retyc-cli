package ui

import (
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
)

// binaryUnits maps a size suffix (lower case) to its power of 1024. Every unit
// is binary, like FormatSize: "G" and "GiB" both mean 1024³ bytes.
var binaryUnits = map[string]int{
	"": 0, "b": 0,
	"k": 1, "kib": 1,
	"m": 2, "mib": 2,
	"g": 3, "gib": 3,
	"t": 4, "tib": 4,
	"p": 5, "pib": 5,
}

// ParseSize parses a positive byte count written as a number and an optional
// binary unit: "1048576", "512B", "50G", "50GiB", "1.5TiB" (case-insensitive,
// blanks allowed between number and unit). The decimal units "KB", "GB", ...
// are refused rather than guessed. A fractional result is rounded down.
func ParseSize(s string) (int64, error) {
	s = strings.TrimSpace(s)
	end := strings.IndexFunc(s, func(r rune) bool { return (r < '0' || r > '9') && r != '.' })
	if end < 0 {
		end = len(s)
	}
	num, unit := s[:end], strings.ToLower(strings.TrimSpace(s[end:]))
	if num == "" {
		return 0, fmt.Errorf("invalid size %q: expected a number such as 50GiB", s)
	}
	exp, ok := binaryUnits[unit]
	if !ok {
		if strings.HasSuffix(unit, "b") && len(unit) == 2 {
			return 0, fmt.Errorf("invalid size %q: units are binary, write %s or %siB",
				s, strings.ToUpper(unit[:1]), strings.ToUpper(unit[:1]))
		}

		return 0, fmt.Errorf("invalid size %q: unknown unit %q (B, K/KiB, M/MiB, G/GiB, T/TiB, P/PiB)", s, unit)
	}
	mult := int64(1) << (10 * exp)

	var size int64
	n, err := strconv.ParseInt(num, 10, 64)
	switch {
	case errors.Is(err, strconv.ErrRange):
		return 0, fmt.Errorf("invalid size %q: too large", s)
	case err == nil:
		if n > math.MaxInt64/mult {
			return 0, fmt.Errorf("invalid size %q: too large", s)
		}
		size = n * mult
	default:
		f, err := strconv.ParseFloat(num, 64)
		if err != nil {
			return 0, fmt.Errorf("invalid size %q: %w", s, err)
		}
		if exp == 0 {
			return 0, fmt.Errorf("invalid size %q: a byte count must be a whole number", s)
		}
		v := f * float64(mult)
		if v >= math.MaxInt64 {
			return 0, fmt.Errorf("invalid size %q: too large", s)
		}
		size = int64(v)
	}
	if size <= 0 {
		return 0, fmt.Errorf("invalid size %q: must be greater than zero", s)
	}

	return size, nil
}
