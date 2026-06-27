package main

import "testing"

func TestParseKeyValueFlags(t *testing.T) {
	got, err := parseKeyValueFlags([]string{"foo=bar", "empty="}, "--var")
	if err != nil {
		t.Fatal(err)
	}
	if got["foo"] != "bar" || got["empty"] != "" {
		t.Fatalf("unexpected parsed values: %#v", got)
	}
}

func TestParseKeyValueFlagsRejectsMalformed(t *testing.T) {
	tests := []string{"novalue", "=value"}
	for _, tt := range tests {
		t.Run(tt, func(t *testing.T) {
			_, err := parseKeyValueFlags([]string{tt}, "--var")
			if err == nil {
				t.Fatal("expected error")
			}
		})
	}
}

func TestParseKeyValueFlagsRejectsDuplicate(t *testing.T) {
	_, err := parseKeyValueFlags([]string{"foo=one", "foo=two"}, "--var")
	if err == nil {
		t.Fatal("expected duplicate error")
	}
}

func TestCheckNoSharedKeysRejectsOverlap(t *testing.T) {
	err := checkNoSharedKeys(
		map[string]string{"foo": "required"},
		map[string]string{"foo": "optional"},
		"--var",
		"--optional-var",
	)
	if err == nil {
		t.Fatal("expected overlap error")
	}
}

func TestCheckNoSharedKeysAllowsDisjoint(t *testing.T) {
	err := checkNoSharedKeys(
		map[string]string{"foo": "required"},
		map[string]string{"bar": "optional"},
		"--var",
		"--optional-var",
	)
	if err != nil {
		t.Fatal(err)
	}
}
