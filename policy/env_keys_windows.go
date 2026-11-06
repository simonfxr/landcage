package policy

import (
	"maps"
	"slices"

	"github.com/simonfxr/landcage/internal/winpsec"
)

// Use the same key comparison as the native Windows environment block.
func envKey(name string) string {
	return winpsec.EnvironmentKey(name)
}

func matchingEnvKey(env Environ, name string) string {
	key := envKey(name)
	for existing := range env {
		if envKey(existing) == key {
			return existing
		}
	}
	return name
}

// cloneEnv preserves spelling while collapsing inherited case variants.
// The lexicographically last name wins, independent of map iteration order.
func cloneEnv(env Environ) Environ {
	result := make(Environ, len(env))
	names := make(map[string]string, len(env))
	for _, name := range slices.Sorted(maps.Keys(env)) {
		key := envKey(name)
		if previous, ok := names[key]; ok {
			delete(result, previous)
		}
		result[name] = env[name]
		names[key] = name
	}
	return result
}
