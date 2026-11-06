//go:build windows

package policy

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/simonfxr/landcage/internal/winpsec"
)

func TestWindowsDryRunCanonicalPlan(t *testing.T) {
	root := t.TempDir()
	ro := filepath.Join(root, "read only.txt")
	psecWriteFile(t, ro)
	rw := filepath.Join(root, "writable")
	if err := os.Mkdir(rw, 0o700); err != nil {
		t.Fatal(err)
	}
	p := psecTestPolicy(
		FSRule{Path: filepath.ToSlash(ro), Access: "rx"},
		FSRule{Path: rw, Access: "rwxcdu", Refer: true, IoctlDev: true},
		FSRule{Path: filepath.Join(root, "missing"), Access: "rx", IgnoreMissing: true},
	)
	p.Description = "dry-run test"
	value := "resolved value"
	p.Env = map[string]EnvEntry{"DRY_RUN_TEST": {Value: &value}}
	var out bytes.Buffer
	if err := DryRun(p, &out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"Policy: windows-test",
		"Description: dry-run test",
		"Windows PSEC API support:",
		"RO (read + execute): " + psecCanonical(t, ro),
		"RW (full read-write directory): " + psecCanonical(t, rw),
		"No implicit grants or ACL changes",
		"runtime/system roots require explicit --ro",
		"Network: deny (all IP networking",
		"Win32k: enabled",
		"UI restrictions: enabled separately",
		"IPC: not Linux-scoped",
		"abstract_unix=allow, signal=allow",
		"not runtime certification",
		"MSYS/Git Bash compatibility validation",
		`DRY_RUN_TEST = "resolved value"`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("output missing %q:\n%s", want, out.String())
		}
	}
	for _, unwanted := range []string{"Landlock", "ABI ", "best-effort deny", "UDP unrestricted", "missing"} {
		if strings.Contains(out.String(), unwanted) {
			t.Errorf("unexpected %q in Windows plan:\n%s", unwanted, out.String())
		}
	}
}

func TestWindowsDryRunRejectsUnsupportedPolicyBeforeOutput(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "file")
	psecWriteFile(t, file)
	tests := []struct {
		name   string
		change func(*Policy)
	}{
		{"network-allow", func(p *Policy) { p.Net.Allow = true }},
		{"network-port", func(p *Policy) { p.Net.Rules = []NetRule{{Port: 443, Access: "connect"}} }},
		{"namespaces", func(p *Policy) { p.Unshare = &UnshareConfig{User: true} }},
		{"ipc-omitted", func(p *Policy) { p.IPC = nil }},
		{"ipc-default", func(p *Policy) { p.IPC.Signal = "" }},
		{"ipc-deny", func(p *Policy) { p.IPC.AbstractUnix = "deny" }},
		{"read-without-execute", func(p *Policy) { p.FS[0].Access = "r" }},
		{"narrow-rw", func(p *Policy) { p.FS[0].Access = "rwx" }},
		{"rw-file", func(p *Policy) {
			p.FS[0] = FSRule{Path: file, Access: "rwxcdu", Refer: true, IoctlDev: true}
		}},
		{"create-dir", func(p *Policy) { p.FS[0].CreateDir = "0700" }},
		{"unsafe-path", func(p *Policy) { p.FS[0].Path = `\\server\share\file` }},
		{"missing-path", func(p *Policy) { p.FS[0].Path = filepath.Join(dir, "missing") }},
		{"late-invalid-rule", func(p *Policy) {
			p.FS = append(p.FS, FSRule{Path: dir, Access: "r"})
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := psecTestPolicy(FSRule{Path: dir, Access: "rx"})
			tt.change(p)
			var out bytes.Buffer
			if err := DryRun(p, &out); err == nil {
				t.Fatal("unsupported policy accepted by dry-run")
			}
			if out.Len() != 0 {
				t.Fatalf("unsupported policy printed a misleading plan:\n%s", out.String())
			}
		})
	}
	var out bytes.Buffer
	if err := DryRun(nil, &out); err == nil || out.Len() != 0 {
		t.Fatalf("nil policy: error %v, output %q", err, out.String())
	}
}

func TestWindowsDryRunEmptyPlanHasNoImplicitGrants(t *testing.T) {
	var out bytes.Buffer
	if err := DryRun(psecTestPolicy(), &out); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out.String(), "Filesystem grants (canonical paths):\n  (none)") {
		t.Fatalf("empty plan did not show absence of grants:\n%s", out.String())
	}
}

func TestWindowsFeatureReportingNoFallback(t *testing.T) {
	for _, err := range []error{nil, winpsec.ErrUnsupported, errors.New("native query failed")} {
		var out bytes.Buffer
		printPSECSupport(&out, err)
		want := "Windows PSEC API support: available (baseline 1.0)"
		if err != nil {
			want = "Windows PSEC API support: unsupported/unavailable (" + err.Error() + ")"
		}
		if !strings.Contains(out.String(), want) || !strings.Contains(out.String(), "not runtime certification") {
			t.Fatalf("incorrect API support report for %v:\n%s", err, out.String())
		}
		if !strings.HasPrefix(out.String(), "Kernel features: Windows PSEC") ||
			strings.Contains(out.String(), "Landlock") || strings.Contains(out.String(), "ABI ") {
			t.Fatalf("native API status fell back to Landlock:\n%s", out.String())
		}
	}
	// Exercise the real query too; this test is valid on unsupported Windows hosts.
	err := winpsec.CheckSupport()
	var want, actual bytes.Buffer
	printPSECSupport(&want, err)
	PrintSandboxFeatures(&actual)
	if actual.String() != want.String() {
		t.Fatalf("feature dispatch did not use native support query:\ngot %s\nwant %s", actual.String(), want.String())
	}
}
