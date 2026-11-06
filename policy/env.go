package policy

import (
	"fmt"
	"maps"
	"slices"
	"strings"
)

// Without returns a copy without the named variables, using the platform's
// environment name comparison.
func (e Environ) Without(names ...string) Environ {
	result := cloneEnv(e)
	for _, name := range names {
		delete(result, matchingEnvKey(result, name))
	}
	return result
}

// ApplyEnv applies environment variable changes from the policy,
// returning a new Environ. All values should already be expanded by
// template rendering at load time. Does not modify the input.
func ApplyEnv(p *Policy, env Environ) (Environ, error) {
	names := slices.Sorted(maps.Keys(p.Env))
	seen := make(map[string]string, len(names))
	for _, name := range names {
		key := envKey(name)
		if previous, ok := seen[key]; ok {
			return nil, fmt.Errorf("duplicate environment policy keys %q and %q", previous, name)
		}
		seen[key] = name
	}

	result := cloneEnv(env)
	for _, name := range names {
		entry := p.Env[name]
		currentName := matchingEnvKey(result, name)
		newVal, unset := resolveEnvEntry(currentName, &entry, result)
		delete(result, currentName)
		if !unset {
			result[name] = newVal
		}
	}
	return result, nil
}

func resolveEnvEntry(name string, e *EnvEntry, env Environ) (string, bool) {
	if e.Unset {
		return "", true
	}
	if e.Value != nil {
		return *e.Value, false
	}

	// Path operation
	sep := e.Sep
	current := env[name]

	// Build set of elements to remove
	removeSet := make(map[string]bool, len(e.Remove))
	for _, r := range e.Remove {
		removeSet[r] = true
	}

	// Split, filter removals
	var parts []string
	if current != "" {
		for p := range strings.SplitSeq(current, sep) {
			if !removeSet[p] {
				parts = append(parts, p)
			}
		}
	}

	// Prepend
	for _, v := range slices.Backward(e.Prepend) {
		parts = append([]string{v}, parts...)
	}

	// Append
	parts = append(parts, e.Append...)

	return strings.Join(parts, sep), false
}
