//go:build !windows

package policy

func envKey(name string) string {
	return name
}

func matchingEnvKey(_ Environ, name string) string {
	return name
}

func cloneEnv(env Environ) Environ {
	return env.Clone()
}
