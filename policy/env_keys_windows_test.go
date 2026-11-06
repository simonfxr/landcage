package policy

import (
	"maps"
	"reflect"
	"testing"
)

func TestApplyEnvWindowsCaseInsensitive(t *testing.T) {
	tests := []struct {
		name   string
		policy string
		want   Environ
	}{
		{"override", `{"PATH":"replacement"}`, Environ{"PATH": "replacement"}},
		{"unset", `{"pAtH":null}`, Environ{}},
		{"append", `{"PATH":{"append":"C","sep":";"}}`, Environ{"PATH": "A;B;C"}},
		{"combined", `{"pAtH":{"prepend":"Z","remove":"A","append":"C","sep":";"}}`, Environ{"pAtH": "Z;B;C"}},
		{"default_separator_unchanged", `{"PATH":{"append":"C"}}`, Environ{"PATH": "A;B:C"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p, err := Parse([]byte(`{"name":"test","env":` + tt.policy + `}`))
			if err != nil {
				t.Fatal(err)
			}
			got, err := ApplyEnv(p, Environ{"Path": "A;B"})
			if err != nil {
				t.Fatal(err)
			}
			if !maps.Equal(got, tt.want) {
				t.Fatalf("ApplyEnv = %#v, want %#v", got, tt.want)
			}
		})
	}
}

func TestApplyEnvWindowsDuplicatePolicyKeys(t *testing.T) {
	for _, source := range []string{
		`{"name":"test","env":{"PATH":"one","Path":null}}`,
		`{"name":"test","env":{"Path":{"append":"one"},"PATH":{"prepend":"two"}}}`,
		// Fold Unicode aliases consistently through policy and native block.
		`{"name":"test","env":{"KEY":"one","\u212aEY":"two"}}`,
		`{"name":"test","env":{"s":"one","\u017f":"two"}}`,
	} {
		p, err := Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		var previous string
		for range 20 {
			got, err := ApplyEnv(p, Environ{"Path": "inherited"})
			if err == nil || got != nil {
				t.Fatalf("ApplyEnv = %#v, %v; want nil and a duplicate-key error", got, err)
			}
			if previous != "" && err.Error() != previous {
				t.Fatalf("nondeterministic error: %q, previously %q", err, previous)
			}
			previous = err.Error()
		}
	}
}

func TestApplyEnvWindowsInheritedCaseVariants(t *testing.T) {
	env := Environ{"PATH": "upper", "Path": "mixed", "path": "lower", "Other": "kept"}
	want := Environ{"path": "lower", "Other": "kept"}
	for range 100 {
		got, err := ApplyEnv(&Policy{}, env)
		if err != nil {
			t.Fatal(err)
		}
		if !maps.Equal(got, want) {
			t.Fatalf("ApplyEnv = %#v, want %#v", got, want)
		}
	}
}

func TestApplyEnvWindowsDoesNotModifyInputs(t *testing.T) {
	for _, source := range []string{
		`{"name":"test","env":{"PATH":{"prepend":"Z","remove":"A","append":"C","sep":";"}}}`,
		`{"name":"test","env":{"PATH":"one","Path":"two"}}`,
	} {
		p, err := Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		wantPolicy, err := Parse([]byte(source))
		if err != nil {
			t.Fatal(err)
		}
		env := Environ{"Path": "A;B", "PATH": "shadowed", "Other": "kept"}
		wantEnv := maps.Clone(env)
		_, _ = ApplyEnv(p, env)
		if !maps.Equal(env, wantEnv) {
			t.Fatalf("input environment mutated: %#v, want %#v", env, wantEnv)
		}
		if !reflect.DeepEqual(p, wantPolicy) {
			t.Fatalf("input policy mutated: %#v, want %#v", p, wantPolicy)
		}
	}
}

func TestEnvironWithoutWindowsPublicPolicyEnv(t *testing.T) {
	env := Environ{
		"LANDCAGE_POLICY_JSON": "upper",
		"landcage_policy_json": "lower",
		"Landcage_Policy_Json": "mixed",
		"Other":                "kept",
	}
	original := maps.Clone(env)
	got := env.Without("LANDCAGE_POLICY_JSON")
	if !maps.Equal(got, Environ{"Other": "kept"}) {
		t.Fatalf("Without leaked public policy environment: %#v", got)
	}
	if !maps.Equal(env, original) {
		t.Fatalf("Without mutated input: %#v, want %#v", env, original)
	}
}
