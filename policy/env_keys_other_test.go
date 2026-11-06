//go:build !windows

package policy

import (
	"maps"
	"testing"
)

func TestApplyEnvCaseSensitiveNames(t *testing.T) {
	p, err := Parse([]byte(`{"name":"test","env":{"PATH":"upper","Path":"mixed","path":null}}`))
	if err != nil {
		t.Fatal(err)
	}
	env := Environ{"PATH": "old-upper", "Path": "old-mixed", "path": "old-lower"}
	got, err := ApplyEnv(p, env)
	if err != nil {
		t.Fatal(err)
	}
	if want := (Environ{"PATH": "upper", "Path": "mixed"}); !maps.Equal(got, want) {
		t.Fatalf("ApplyEnv = %#v, want %#v", got, want)
	}
}

func TestEnvironWithoutCaseSensitiveNames(t *testing.T) {
	env := Environ{"LANDCAGE_POLICY_JSON": "upper", "landcage_policy_json": "lower"}
	got := env.Without("LANDCAGE_POLICY_JSON")
	if want := (Environ{"landcage_policy_json": "lower"}); !maps.Equal(got, want) {
		t.Fatalf("Without = %#v, want %#v", got, want)
	}
	if len(env) != 2 {
		t.Fatalf("Without mutated input: %#v", env)
	}
}
