package policy

import (
	"strings"
)

// ApplyEnv applies environment variable changes from the policy,
// returning a new Environ. All values should already be expanded by
// template rendering at load time. Does not modify the input.
func ApplyEnv(p *Policy, env Environ) (Environ, error) {
	result := env.Clone()

	for name, entry := range p.Env {
		newVal, unset := resolveEnvEntry(name, &entry, result)
		if unset {
			delete(result, name)
		} else {
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
	for i := len(e.Prepend) - 1; i >= 0; i-- {
		parts = append([]string{e.Prepend[i]}, parts...)
	}

	// Append
	parts = append(parts, e.Append...)

	return strings.Join(parts, sep), false
}
