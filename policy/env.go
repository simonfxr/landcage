package policy

import (
	"strings"
)

// ApplyEnv expands and applies environment variable changes from the policy,
// returning a new Environ. Does not modify the input or process environment.
func ApplyEnv(p *Policy, opts *Options) (Environ, error) {
	exp := NewExpander(opts)
	result := opts.Env.Clone()

	for name, entry := range p.Env {
		newVal, unset, err := resolveEnvEntry(name, &entry, exp, result)
		if err != nil {
			return nil, err
		}
		if unset {
			delete(result, name)
		} else {
			result[name] = newVal
		}
	}
	return result, nil
}

func resolveEnvEntry(name string, e *EnvEntry, exp *Expander, env Environ) (string, bool, error) {
	if e.Unset {
		return "", true, nil
	}
	if e.Value != nil {
		expanded, err := exp.Expand(*e.Value)
		if err != nil {
			return "", false, err
		}
		return expanded.String(), false, nil
	}

	// Path operation
	sep := e.Sep
	current := env[name]

	// Build set of elements to remove
	removeSet := make(map[string]bool, len(e.Remove))
	for _, r := range e.Remove {
		expanded, err := exp.Expand(r)
		if err != nil {
			return "", false, err
		}
		removeSet[expanded.String()] = true
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
		expanded, err := exp.Expand(e.Prepend[i])
		if err != nil {
			return "", false, err
		}
		parts = append([]string{expanded.String()}, parts...)
	}

	// Append
	for _, a := range e.Append {
		expanded, err := exp.Expand(a)
		if err != nil {
			return "", false, err
		}
		parts = append(parts, expanded.String())
	}

	return strings.Join(parts, sep), false, nil
}
