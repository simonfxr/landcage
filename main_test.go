package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/alexflint/go-arg"
)

func TestCLIRequiresDashBeforeCommand(t *testing.T) {
	var a args
	p, err := arg.NewParser(arg.Config{}, &a)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse([]string{"--ro", "/", "true"}); err != nil {
		t.Fatal(err)
	}
	if err := setCommandArgs(&a, nil); err == nil {
		t.Fatal("expected command without -- to be rejected by CLI validation")
	}

	before, command := splitAtDash([]string{"--ro", "/", "--", "true", "--help"})
	a = args{}
	p, err = arg.NewParser(arg.Config{}, &a)
	if err != nil {
		t.Fatal(err)
	}
	if err := p.Parse(before); err != nil {
		t.Fatal(err)
	}
	if err := setCommandArgs(&a, command); err != nil {
		t.Fatal(err)
	}
	if len(a.Cmd) != 2 || a.Cmd[0] != "true" || a.Cmd[1] != "--help" {
		t.Fatalf("unexpected command: %#v", a.Cmd)
	}
}

func TestPrintKernelFeatures(t *testing.T) {
	var out bytes.Buffer
	printKernelFeatures(&out)
	if !strings.HasPrefix(out.String(), "Kernel features: ") {
		t.Fatalf("unexpected output: %q", out.String())
	}
}

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
