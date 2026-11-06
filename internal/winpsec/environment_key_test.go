package winpsec

import "testing"

func TestEnvironmentKeyAliases(t *testing.T) {
	for _, pair := range [][2]string{{"Path", "PATH"}, {"KEY", "KEY"}, {"s", "ſ"}} {
		if EnvironmentKey(pair[0]) != EnvironmentKey(pair[1]) {
			t.Errorf("environment aliases disagree: %q and %q", pair[0], pair[1])
		}
	}
	for _, name := range []string{"Path", "KEY", "ſ", "Σ", "ß"} {
		key := EnvironmentKey(name)
		if EnvironmentKey(key) != key {
			t.Errorf("non-idempotent environment key for %q", name)
		}
	}
}
