package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// resolvePath resolves a path that may contain glob metacharacters in the
// final path component. Returns the matched paths, or the literal path if no
// glob characters are present.
func resolvePath(path string) ([]string, error) {
	if !hasGlobMeta(path) {
		return []string{path}, nil
	}

	dir, base := filepath.Split(path)
	if dir != "/" {
		dir = strings.TrimRight(dir, "/")
	}
	if dir == "" {
		dir = "."
	}

	// Globs in intermediate components are not supported
	if hasGlobMeta(dir) {
		return nil, fmt.Errorf("glob patterns only allowed in the final path component: %q", path)
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	var matches []string
	for _, entry := range entries {
		matched, err := filepath.Match(base, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("bad glob pattern %q: %w", base, err)
		}
		if matched {
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}
	return matches, nil
}

func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}
