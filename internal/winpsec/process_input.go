package winpsec

import (
	"fmt"
	"slices"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

func validProcessString(s string) bool {
	return utf8.ValidString(s) && !strings.ContainsRune(s, 0)
}

// EnvironmentKey is shared by Windows policy evaluation and block construction.
// Fold both directions so Unicode aliases such as Kelvin K and long s cannot
// evade policy duplicate detection then collide during block construction.
func EnvironmentKey(name string) string {
	return strings.ToUpper(strings.ToLower(name))
}

// commandLine follows the Windows CRT/CommandLineToArgvW convention, not shell
// syntax. argv[0] has different quoting rules from all subsequent arguments.
func commandLine(argv []string) ([]uint16, error) {
	if len(argv) == 0 || argv[0] == "" {
		return nil, fmt.Errorf("full argv must include a nonempty argv[0]")
	}
	if strings.ContainsRune(argv[0], '"') {
		return nil, fmt.Errorf("Windows argv[0] cannot contain a quotation mark")
	}
	var b strings.Builder
	for i, arg := range argv {
		if !validProcessString(arg) {
			return nil, fmt.Errorf("argv[%d] must be UTF-8 without NUL", i)
		}
		if i == 0 {
			if strings.ContainsFunc(arg, func(r rune) bool { return r <= ' ' }) {
				b.WriteByte('"')
				b.WriteString(arg)
				b.WriteByte('"')
			} else {
				b.WriteString(arg)
			}
		} else {
			b.WriteByte(' ')
			b.WriteString(quoteArgument(arg))
		}
	}
	result := append(utf16.Encode([]rune(b.String())), 0)
	if len(result) > 32767 {
		return nil, fmt.Errorf("Windows command line exceeds 32767 UTF-16 code units")
	}
	return result, nil
}

func quoteArgument(arg string) string {
	if arg != "" && !strings.ContainsAny(arg, " \t\"") {
		return arg
	}
	var b strings.Builder
	b.WriteByte('"')
	slashes := 0
	for _, r := range arg {
		if r == '\\' {
			slashes++
			continue
		}
		if r == '"' {
			b.WriteString(strings.Repeat("\\", slashes*2+1))
		} else {
			b.WriteString(strings.Repeat("\\", slashes))
		}
		slashes = 0
		b.WriteRune(r)
	}
	b.WriteString(strings.Repeat("\\", slashes*2))
	b.WriteByte('"')
	return b.String()
}

// environmentBlock never inherits the parent environment, including for nil.
// Duplicate names are case-insensitive and last-wins. Preserve
// Windows' per-drive current directories (=C:=...) when explicitly supplied.
func environmentBlock(env []string) ([]uint16, error) {
	type entry struct {
		key   []uint16
		value string
	}
	entries := make(map[string]entry, len(env))
	for _, value := range env {
		if !validProcessString(value) {
			return nil, fmt.Errorf("environment entry must be UTF-8 without NUL")
		}
		separator := strings.IndexByte(value, '=')
		if separator == 0 && len(value) >= 4 && value[2] == ':' && value[3] == '=' &&
			(value[1] >= 'A' && value[1] <= 'Z' || value[1] >= 'a' && value[1] <= 'z') {
			separator = 3
		}
		if separator <= 0 {
			return nil, fmt.Errorf("environment entry must have a nonempty name and '=': %q", value)
		}
		key := EnvironmentKey(value[:separator])
		entries[key] = entry{utf16.Encode([]rune(key)), value}
	}
	sorted := make([]entry, 0, len(entries))
	for _, item := range entries {
		sorted = append(sorted, item)
	}
	slices.SortFunc(sorted, func(a, b entry) int { return slices.Compare(a.key, b.key) })
	var block []uint16
	for _, item := range sorted {
		block = append(block, utf16.Encode([]rune(item.value))...)
		block = append(block, 0)
	}
	if len(block) == 0 {
		block = append(block, 0)
	}
	return append(block, 0), nil
}
