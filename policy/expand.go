package policy

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// PathSegment is a piece of an expanded path.
type PathSegment struct {
	Text    string
	FromVar bool // true = from variable substitution (always literal, never globbed)
}

// ExpandedPath is the result of expanding a template string.
type ExpandedPath []PathSegment

// String joins all segments into a plain path string.
func (ep ExpandedPath) String() string {
	var buf strings.Builder
	for _, seg := range ep {
		buf.WriteString(seg.Text)
	}
	return buf.String()
}

// Resolve returns matching filesystem paths. Glob metacharacters (*, ?, [) in
// FromVar=false segments of the final path component are expanded. FromVar=true
// segments are always literal.
func (ep ExpandedPath) Resolve() ([]string, error) {
	full := ep.String()
	if full == "" {
		return nil, nil
	}

	dir, base := filepath.Split(full)
	if dir != "/" {
		dir = strings.TrimRight(dir, "/")
	}
	if dir == "" {
		dir = "."
	}

	// Check for globs in non-final components (error) — only from literal segments
	dirLen := len(full) - len(base)
	pos := 0
	for _, seg := range ep {
		segEnd := pos + len(seg.Text)
		if segEnd > dirLen {
			break
		}
		if !seg.FromVar && hasGlobMeta(seg.Text) {
			return nil, fmt.Errorf("glob patterns only allowed in the final path component: %q", full)
		}
		pos = segEnd
	}
	// Check segment that straddles the dir/base boundary
	pos = 0
	for _, seg := range ep {
		segEnd := pos + len(seg.Text)
		if pos < dirLen && segEnd > dirLen && !seg.FromVar {
			dirPortion := seg.Text[:dirLen-pos]
			if hasGlobMeta(dirPortion) {
				return nil, fmt.Errorf("glob patterns only allowed in the final path component: %q", full)
			}
		}
		pos = segEnd
	}

	// Determine if any literal (non-variable) segment in the base contains glob chars.
	hasGlob := false
	pos = 0
	for _, seg := range ep {
		segEnd := pos + len(seg.Text)
		// Does this segment overlap with the base portion?
		if segEnd > dirLen && !seg.FromVar {
			// The part of this segment within the base
			start := 0
			if pos < dirLen {
				start = dirLen - pos
			}
			portion := seg.Text[start:]
			if hasGlobMeta(portion) {
				hasGlob = true
				break
			}
		}
		pos = segEnd
	}

	if !hasGlob {
		return []string{full}, nil
	}

	// Build a filepath.Match pattern for the base: escape glob chars in FromVar=true segments
	var pattern strings.Builder
	pos = 0
	for _, seg := range ep {
		segEnd := pos + len(seg.Text)
		if segEnd <= dirLen {
			pos = segEnd
			continue
		}
		start := 0
		if pos < dirLen {
			start = dirLen - pos
		}
		portion := seg.Text[start:]
		if seg.FromVar {
			// Escape glob metacharacters for filepath.Match
			for _, ch := range portion {
				if ch == '*' || ch == '?' || ch == '[' || ch == '\\' {
					pattern.WriteByte('\\')
				}
				pattern.WriteRune(ch)
			}
		} else {
			pattern.WriteString(portion)
		}
		pos = segEnd
	}

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	pat := pattern.String()
	var matches []string
	for _, entry := range entries {
		matched, err := filepath.Match(pat, entry.Name())
		if err != nil {
			return nil, fmt.Errorf("bad glob pattern %q: %w", pat, err)
		}
		if matched {
			matches = append(matches, filepath.Join(dir, entry.Name()))
		}
	}
	return matches, nil
}

// hasGlobMeta checks for unescaped glob metacharacters in a string.
func hasGlobMeta(s string) bool {
	return strings.ContainsAny(s, "*?[")
}

// Expander handles variable expansion in path strings.
type Expander struct {
	builtins map[string]string
	env      Environ
}

// NewExpander creates an Expander from Options.
func NewExpander(opts *Options) *Expander {
	return &Expander{
		builtins: map[string]string{
			"home":       opts.Dirs.Home,
			"uid":        opts.UID,
			"user":       opts.User,
			"pwd":        opts.Dirs.Pwd,
			"configDir":  opts.Dirs.ConfigDir,
			"dataDir":    opts.Dirs.DataDir,
			"cacheDir":   opts.Dirs.CacheDir,
			"stateDir":   opts.Dirs.StateDir,
			"runtimeDir": opts.Dirs.RuntimeDir,
			"tmpDir":     opts.Dirs.TmpDir,
		},
		env: opts.Env,
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// Expand expands all ${...} references in s, returning an ExpandedPath
// that tracks which segments came from variable substitution.
func (e *Expander) Expand(s string) (ExpandedPath, error) {
	var segs ExpandedPath
	i := 0
	litStart := 0
	for i < len(s) {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			if litStart < i {
				segs = append(segs, PathSegment{Text: s[litStart:i], FromVar: false})
			}
			end, varSegs, err := e.expandRef(s, i+2)
			if err != nil {
				return nil, err
			}
			segs = append(segs, varSegs...)
			i = end
			litStart = end
		} else {
			i++
		}
	}
	if litStart < len(s) {
		segs = append(segs, PathSegment{Text: s[litStart:], FromVar: false})
	}
	return segs, nil
}

// expandRef parses from position after "${", returns position after "}" and the expanded segments.
func (e *Expander) expandRef(s string, start int) (int, ExpandedPath, error) {
	// Find matching '}' accounting for nested ${...}
	depth := 1
	i := start
	for i < len(s) && depth > 0 {
		if i+1 < len(s) && s[i] == '$' && s[i+1] == '{' {
			depth++
			i += 2
		} else if s[i] == '}' {
			depth--
			if depth == 0 {
				break
			}
			i++
		} else {
			i++
		}
	}
	if depth != 0 {
		return 0, nil, fmt.Errorf("unterminated ${...} starting at position %d", start-2)
	}

	inner := s[start:i]
	end := i + 1

	varName, fallback, hasFallback := splitDefault(inner)

	val := e.resolve(varName)
	if val != "" {
		return end, ExpandedPath{{Text: val, FromVar: true}}, nil
	}

	if hasFallback {
		// Recursively expand fallback — nested ${} produce FromVar=true, literal text produces FromVar=false
		expanded, err := e.Expand(fallback)
		if err != nil {
			return 0, nil, err
		}
		return end, expanded, nil
	}

	return 0, nil, fmt.Errorf("variable %q is unset and has no default", varName)
}

// resolve looks up a variable: builtins first, then env.
func (e *Expander) resolve(name string) string {
	if v, ok := e.builtins[name]; ok {
		return v
	}
	return e.env[name]
}

// splitDefault splits "VAR:-default" into (name, default, true)
// or "VAR" into (name, "", false).
func splitDefault(s string) (string, string, bool) {
	before, after, ok := strings.Cut(s, ":-")
	if !ok {
		return s, "", false
	}
	return before, after, true
}
