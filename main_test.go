package main

import (
	"bytes"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
)

func TestCLIRWPathRules(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0600); err != nil {
		t.Fatal(err)
	}
	socket := filepath.Join(dir, "socket")
	ln, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	link := filepath.Join(dir, "link")
	if err := os.Symlink(file, link); err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name, path, access string
		refer              bool
	}{
		{"directory", dir, "rwxcdu", true},
		{"file", file, "rwxu", false},
		{"socket", socket, "rwxu", false},
		{"device", "/dev/null", "rwxu", false},
		{"symlink", link, "rwxu", false},
		{"missing", filepath.Join(dir, "missing"), "rwxcdu", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a := args{RW: []string{tc.path}, RO: []string{dir}}
			p, err := arg.NewParser(arg.Config{}, &a)
			if err != nil {
				t.Fatal(err)
			}
			pol := buildPolicy(&a, p)
			want := policy.FSRule{
				Path: tc.path, Access: tc.access, Refer: tc.refer,
				IoctlDev: true, IgnoreMissing: true,
			}
			if len(pol.FS) != 2 || pol.FS[1] != want {
				t.Fatalf("unexpected rules: %#v; want RW %#v", pol.FS, want)
			}
			if ro := pol.FS[0]; ro.Access != "rx" || ro.IoctlDev || ro.Refer {
				t.Fatalf("--ro changed: %#v", ro)
			}
			var out bytes.Buffer
			if err := policy.DryRun(pol, &out); err != nil {
				t.Fatalf("invalid generated policy: %v", err)
			}
			if tc.name == "directory" && strings.Contains(out.String(), "ioctl_dev has no effect") {
				t.Fatal("directory ioctl grant incorrectly reported as ineffective")
			}
		})
	}
}

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

func TestScrubDYLDLeavesPolicyKeys(t *testing.T) {
	kept := "from-policy"
	pol := &policy.Policy{Env: map[string]policy.EnvEntry{
		"DYLD_LIBRARY_PATH": {Value: &kept},
	}}
	env := policy.Environ{
		"DYLD_INSERT_LIBRARIES":      "/evil.dylib",
		"DYLD_LIBRARY_PATH":          kept,
		"DYLD_FRAMEWORK_PATH":        "/fw",
		"DYLD_FALLBACK_LIBRARY_PATH": "/fb",
		"DYLD_ROOT_PATH":             "/root",
		"PATH":                       "/usr/bin",
	}
	scrubDYLD(pol, env)
	if _, ok := env["DYLD_INSERT_LIBRARIES"]; ok {
		t.Fatal("DYLD_INSERT_LIBRARIES was not unset")
	}
	if _, ok := env["DYLD_FRAMEWORK_PATH"]; ok || env["DYLD_FALLBACK_LIBRARY_PATH"] != "" || env["DYLD_ROOT_PATH"] != "" {
		t.Fatalf("dyld vars not scrubbed: %#v", env)
	}
	if env["DYLD_LIBRARY_PATH"] != kept {
		t.Fatalf("policy key = %q", env["DYLD_LIBRARY_PATH"])
	}
	if env["PATH"] != "/usr/bin" {
		t.Fatalf("PATH = %q", env["PATH"])
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
