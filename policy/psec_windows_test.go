//go:build windows

package policy

import (
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/simonfxr/landcage/internal/winpsec"
)

func psecTestPolicy(rules ...FSRule) *Policy {
	return &Policy{
		Name: "windows-test",
		FS:   rules,
		IPC:  &IPCConfig{AbstractUnix: "allow", Signal: "allow"},
	}
}

func psecCanonical(t *testing.T, path string) string {
	t.Helper()
	result, err := filepath.EvalSymlinks(path)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func psecWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestCompilePSECExplicitGrants(t *testing.T) {
	root := t.TempDir()
	file := filepath.Join(root, "read only.txt")
	psecWriteFile(t, file)
	rw := filepath.Join(root, "writable")
	if err := os.Mkdir(rw, 0o700); err != nil {
		t.Fatal(err)
	}
	p := psecTestPolicy(
		FSRule{Path: root, Access: "rx"},
		FSRule{Path: file, Access: "xrrx"},
		FSRule{Path: rw, Access: "udcxwr", Refer: true, IoctlDev: true},
	)
	spec, err := CompilePSEC(p)
	if err != nil {
		t.Fatal(err)
	}
	want := winpsec.Spec{
		ReadOnlyPaths:  []string{psecCanonical(t, root), psecCanonical(t, file)},
		ReadWritePaths: []string{psecCanonical(t, rw)},
		Network:        winpsec.NetworkDeny,
	}
	if !reflect.DeepEqual(spec, want) {
		t.Fatalf("spec = %#v, want %#v", spec, want)
	}
	if _, err := winpsec.Encode(spec); err != nil {
		t.Fatal(err)
	}
	if p.FS[2].Access != "udcxwr" || p.FS[2].Path != rw {
		t.Fatal("compilation modified the input policy")
	}
	empty, err := CompilePSEC(psecTestPolicy())
	if err != nil || !reflect.DeepEqual(empty, winpsec.Spec{Network: winpsec.NetworkDeny}) {
		t.Fatalf("empty policy acquired implicit grants: %#v, %v", empty, err)
	}
}

func TestCompilePSECRejectAccessWidening(t *testing.T) {
	dir := t.TempDir()
	tests := []struct {
		name string
		rule FSRule
	}{
		{"read-without-execute", FSRule{Access: "r"}},
		{"execute-only", FSRule{Access: "x"}},
		{"empty", FSRule{}},
		{"unknown-access", FSRule{Access: "rxz"}},
		{"ro-refer", FSRule{Access: "rx", Refer: true}},
		{"ro-ioctl", FSRule{Access: "rx", IoctlDev: true}},
		{"rw-no-refer", FSRule{Access: "rwxcdu", IoctlDev: true}},
		{"rw-no-ioctl", FSRule{Access: "rwxcdu", Refer: true}},
		{"rw-no-unix", FSRule{Access: "rwxcd", Refer: true, IoctlDev: true}},
		{"rw-no-delete", FSRule{Access: "rwxcu", Refer: true, IoctlDev: true}},
		{"rw-no-create", FSRule{Access: "rwxdu", Refer: true, IoctlDev: true}},
		{"rw-file-shortcut", FSRule{Access: "rwxu", IoctlDev: true}},
		{"missing-unsupported-rule", FSRule{Path: filepath.Join(dir, "absent"), Access: "r", IgnoreMissing: true}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rule := tt.rule
			if rule.Path == "" {
				rule.Path = dir
			}
			if _, err := CompilePSEC(psecTestPolicy(rule)); err == nil || !strings.Contains(err.Error(), "unsupported access") {
				t.Fatalf("expected access rejection, got %v", err)
			}
		})
	}
	file := filepath.Join(dir, "file")
	psecWriteFile(t, file)
	_, err := CompilePSEC(psecTestPolicy(FSRule{Path: file, Access: "rwxcdu", Refer: true, IoctlDev: true}))
	if err == nil || !strings.Contains(err.Error(), "read-write files") {
		t.Fatalf("expected RW-file rejection, got %v", err)
	}
}

func TestCompilePSECRejectUnsupportedIsolation(t *testing.T) {
	tests := []struct {
		name   string
		change func(*Policy)
		want   string
	}{
		{"network-allow", func(p *Policy) { p.Net.Allow = true }, "network deny"},
		{"network-port", func(p *Policy) { p.Net.Rules = []NetRule{{Port: 443, Access: "connect"}} }, "per-port"},
		{"network-allow-and-port", func(p *Policy) {
			p.Net = NetConfig{Allow: true, Rules: []NetRule{{Port: 80, Access: "connect"}}}
		}, "network deny"},
		{"ipc-nil", func(p *Policy) { p.IPC = nil }, "IPC isolation"},
		{"ipc-empty", func(p *Policy) { p.IPC = &IPCConfig{} }, "IPC isolation"},
		{"ipc-abstract-default", func(p *Policy) { p.IPC.AbstractUnix = "" }, "IPC isolation"},
		{"ipc-signal-default", func(p *Policy) { p.IPC.Signal = "" }, "IPC isolation"},
		{"ipc-abstract-deny", func(p *Policy) { p.IPC.AbstractUnix = "deny" }, "IPC isolation"},
		{"ipc-signal-deny", func(p *Policy) { p.IPC.Signal = "deny" }, "IPC isolation"},
		{"ipc-invalid", func(p *Policy) { p.IPC.Signal = "invalid" }, "IPC isolation"},
		{"unshare-user", func(p *Policy) { p.Unshare = &UnshareConfig{User: true} }, "unshare"},
		{"unshare-pid", func(p *Policy) { p.Unshare = &UnshareConfig{PID: true} }, "unshare"},
		{"unshare-cgroup", func(p *Policy) { p.Unshare = &UnshareConfig{Cgroup: true} }, "unshare"},
		{"unshare-mount-proc", func(p *Policy) { p.Unshare = &UnshareConfig{MountProc: true} }, "unshare"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := psecTestPolicy()
			tt.change(p)
			_, err := CompilePSEC(p)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q rejection, got %v", tt.want, err)
			}
		})
	}
	if _, err := CompilePSEC(nil); err == nil {
		t.Fatal("nil policy accepted")
	}
	p := psecTestPolicy()
	p.Unshare = &UnshareConfig{}
	if _, err := CompilePSEC(p); err != nil {
		t.Fatalf("disabled unshare rejected: %v", err)
	}
}

func TestCompilePSECGlobsAndMissing(t *testing.T) {
	dir := t.TempDir()
	a, b := filepath.Join(dir, "a.txt"), filepath.Join(dir, "b.txt")
	psecWriteFile(t, a)
	psecWriteFile(t, b)
	psecWriteFile(t, filepath.Join(dir, "other"))
	tests := []struct {
		name    string
		path    string
		ignore  bool
		want    []string
		wantErr string
	}{
		{"glob", filepath.Join(dir, "*.txt"), false, []string{psecCanonical(t, a), psecCanonical(t, b)}, ""},
		{"missing-literal", filepath.Join(dir, "absent"), false, nil, "fs rule 0"},
		{"ignored-literal", filepath.Join(dir, "absent"), true, nil, ""},
		{"empty-glob", filepath.Join(dir, "*.absent"), false, nil, "glob matched no paths"},
		{"ignored-empty-glob", filepath.Join(dir, "*.absent"), true, nil, ""},
		{"missing-glob-parent", filepath.Join(dir, "absent", "*"), false, nil, "fs rule 0"},
		{"ignored-glob-parent", filepath.Join(dir, "absent", "*"), true, nil, ""},
		{"intermediate-glob", filepath.Join(dir, "*", "file"), true, nil, "final path component"},
		{"malformed-glob", filepath.Join(dir, "["), true, nil, "bad glob pattern"},
		{"empty", "", false, nil, "drive-absolute"},
		{"ignored-empty", "", true, nil, ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			spec, err := CompilePSEC(psecTestPolicy(FSRule{Path: tt.path, Access: "rx", IgnoreMissing: tt.ignore}))
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil || !reflect.DeepEqual(spec.ReadOnlyPaths, tt.want) {
				t.Fatalf("paths = %v, error = %v; want %v", spec.ReadOnlyPaths, err, tt.want)
			}
		})
	}
}

func TestCompilePSECForwardSlashRootGlob(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	marker := "landcage-root-glob-" + filepath.Base(filepath.Dir(dir))
	psecWriteFile(t, filepath.Join(dir, marker))
	// The marker exists in this drive's current directory, not at its root.
	// The shared resolver must never trim C:/ into the ambiguous root C:.
	pattern := filepath.VolumeName(dir) + "/*" + marker
	spec, err := CompilePSEC(psecTestPolicy(FSRule{Path: pattern, Access: "rx", IgnoreMissing: true}))
	if err != nil || len(spec.ReadOnlyPaths) != 0 {
		t.Fatalf("root glob resolved against drive current directory: %#v, %v", spec, err)
	}
}

func TestCompilePSECErrorDiscardsPartialGrants(t *testing.T) {
	dir := t.TempDir()
	spec, err := CompilePSEC(psecTestPolicy(
		FSRule{Path: dir, Access: "rx"},
		FSRule{Path: dir, Access: "r"},
	))
	if err == nil || !reflect.DeepEqual(spec, winpsec.Spec{}) {
		t.Fatalf("error returned a partial grant: %#v, %v", spec, err)
	}
}

func TestCompilePSECRejectUnsafePaths(t *testing.T) {
	dir := t.TempDir()
	paths := []string{
		"relative", ".", `C:relative`, `C:`, `\rooted`, `/rooted`,
		`\\server\share\file`, `//server/share/file`,
		`\\?\C:\Windows`, `\\.\C:\Windows`, `\??\C:\Windows`,
		`\\?\UNC\server\share`, `\\?\Volume{00000000-0000-0000-0000-000000000000}\`,
		`1:\file`, `C:\file:stream`, `C:\file::$DATA`, `C:\file` + "\x00",
		`C:\bad` + "\x01", `C:\bad` + string([]byte{0xff}),
		`C:\CON`, `C:\NUL.txt`, `C:\COM1`, `C:\LPT9`,
		`C:\con.txt`, `C:\PRN.log`, `C:\AUX.data`, `C:\NUL .txt`,
		`C:\COM1.log`, `C:\lpt9.txt`, `C:\COM¹.log`, `C:\LPT².txt`, `C:\COM³`,
		`C:\CONIN$.txt`, `C:\CONOUT$.log`,
		`C:\trailing.`, `C:\trailing `, `C:\bad|name`, `C:\bad<name`, `C:\bad"name`,
		filepath.Join(dir, "child") + `\..\sibling`,
	}
	for _, path := range paths {
		t.Run(path, func(t *testing.T) {
			// IgnoreMissing must not turn invalid namespaces into valid policy.
			_, err := CompilePSEC(psecTestPolicy(FSRule{Path: path, Access: "rx", IgnoreMissing: true}))
			if err == nil {
				t.Fatalf("unsafe path accepted: %q", path)
			}
		})
	}
	// An explicit, local drive root is unambiguous (unlike C: or \).
	if err := validatePSECPath(filepath.VolumeName(dir) + `\`); err != nil {
		t.Fatalf("local drive root rejected: %v", err)
	}
}

func TestPSECReservedBasenames(t *testing.T) {
	root := filepath.VolumeName(t.TempDir()) + `\`
	for _, name := range []string{"CON", "nul.txt", "NUL .txt", "COM1.log", "LPT9.data", "COM¹.txt", "LPT²", "COM³", "conin$.log", "CONOUT$"} {
		if validatePSECPath(root+name) == nil {
			t.Errorf("reserved basename accepted: %q", name)
		}
	}
	for _, name := range []string{"console", "null.txt", "COM0", "COM10", "LPT0", "LPT10", "COM⁴", "file.NUL", "normal"} {
		if validatePSECPath(root+name) != nil {
			t.Errorf("ordinary basename rejected: %q", name)
		}
	}
}

func TestCompilePSECCanonicalPathsAndLinks(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	psecWriteFile(t, target)
	forwardSlashes := filepath.ToSlash(target)
	spec, err := CompilePSEC(psecTestPolicy(FSRule{Path: forwardSlashes, Access: "rx"}))
	if err != nil || !reflect.DeepEqual(spec.ReadOnlyPaths, []string{psecCanonical(t, target)}) {
		t.Fatalf("slash normalization: %#v, %v", spec, err)
	}
	t.Run("symlink", func(t *testing.T) {
		link := filepath.Join(dir, "link")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("Windows symlink privilege/developer mode unavailable: %v", err)
		}
		if _, err := CompilePSEC(psecTestPolicy(FSRule{Path: link, Access: "rx"})); err == nil || !strings.Contains(err.Error(), "reparse") {
			t.Fatalf("symlink not rejected: %v", err)
		}
		if err := os.Remove(target); err != nil {
			t.Fatal(err)
		}
		if _, err := CompilePSEC(psecTestPolicy(FSRule{Path: link, Access: "rx"})); err == nil {
			t.Fatal("dangling symlink accepted")
		}
		if _, err := CompilePSEC(psecTestPolicy(FSRule{Path: link, Access: "rx", IgnoreMissing: true})); err == nil || !strings.Contains(err.Error(), "reparse") {
			t.Fatalf("IgnoreMissing bypassed dangling reparse rejection: %v", err)
		}
	})
}

func TestCompilePSECRejectsJunctionsBeforeTraversal(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "target")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	psecWriteFile(t, filepath.Join(target, "file"))
	junction := filepath.Join(root, "junction")
	if out, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", junction, target).CombinedOutput(); err != nil {
		t.Fatalf("creating unprivileged junction: %v: %s", err, out)
	}
	for _, path := range []string{junction, filepath.Join(junction, "file"), filepath.Join(junction, "*"), filepath.Join(root, "j*")} {
		for _, ignore := range []bool{false, true} {
			_, err := CompilePSEC(psecTestPolicy(FSRule{Path: path, Access: "rx", IgnoreMissing: ignore}))
			if err == nil || !strings.Contains(err.Error(), "reparse") {
				t.Errorf("junction path %q (IgnoreMissing=%t): %v", path, ignore, err)
			}
		}
	}
}

func TestCompilePSECNoCreationOrEnvironmentExpansion(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "not-created")
	for _, path := range []string{missing, dir} {
		_, err := CompilePSEC(psecTestPolicy(FSRule{Path: path, Access: "rx", CreateDir: "0700"}))
		if err == nil || !strings.Contains(err.Error(), "create_dir") {
			t.Fatalf("expected create_dir rejection, got %v", err)
		}
	}
	if _, err := os.Stat(missing); !os.IsNotExist(err) {
		t.Fatalf("compiler created a directory: %v", err)
	}
	t.Setenv("LANDCAGE_PSEC_PATH_TEST", dir)
	if _, err := CompilePSEC(psecTestPolicy(FSRule{Path: "%LANDCAGE_PSEC_PATH_TEST%", Access: "rx"})); err == nil {
		t.Fatal("compiler performed unexpected environment expansion")
	}
	// Environment interpolation belongs to template loading, not compilation.
	file := filepath.Join(dir, "$literal")
	psecWriteFile(t, file)
	spec, err := CompilePSEC(psecTestPolicy(FSRule{Path: file, Access: "rx"}))
	if err != nil || !reflect.DeepEqual(spec.ReadOnlyPaths, []string{psecCanonical(t, file)}) {
		t.Fatalf("literal dollar path: %#v, %v", spec, err)
	}
}
