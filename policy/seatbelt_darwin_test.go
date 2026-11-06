//go:build darwin && cgo

package policy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

const seatbeltHelperEnv = "LANDCAGE_TEST_SEATBELT"

type seatbeltProbe struct {
	Op   string
	Path string
	Deny bool
}

type seatbeltRequest struct {
	Profile string
	Params  []string
	Probes  []seatbeltProbe
}

// Seatbelt is irreversible and process-wide: only this re-executed helper
// applies a profile. Compilation and fixture cleanup stay in the parent.
func TestSeatbeltEnforceHelper(t *testing.T) {
	data := os.Getenv(seatbeltHelperEnv)
	if data == "" {
		return
	}
	var req seatbeltRequest
	if err := json.Unmarshal([]byte(data), &req); err != nil {
		t.Fatal(err)
	}
	if err := Apply(req.Profile, req.Params); err != nil {
		t.Fatalf("apply Seatbelt profile: %v", err)
	}
	for _, probe := range req.Probes {
		err := probe.run()
		if probe.Deny {
			if !errors.Is(err, syscall.EPERM) && !errors.Is(err, syscall.EACCES) {
				t.Errorf("%s %s: want permission denial, got %v", probe.Op, probe.Path, err)
			}
		} else if err != nil {
			t.Errorf("%s %s: want allowed, got %v", probe.Op, probe.Path, err)
		}
	}
}

func (p seatbeltProbe) run() error {
	switch p.Op {
	case "read":
		_, err := os.ReadFile(p.Path)
		return err
	case "write":
		f, err := os.OpenFile(p.Path, os.O_WRONLY, 0)
		if err != nil {
			return err
		}
		defer f.Close()
		_, err = f.Write([]byte("changed"))
		return err
	case "exec":
		return exec.Command(p.Path).Run()
	case "connect":
		c, err := net.DialTimeout("unix", p.Path, 2*time.Second)
		if err != nil {
			return err
		}
		return c.Close()
	case "listen":
		l, err := net.ListenUnix("unix", &net.UnixAddr{Net: "unix", Name: p.Path})
		if err != nil {
			return err
		}
		// A create-only policy need not permit unlink; the parent cleans up.
		l.SetUnlinkOnClose(false)
		return l.Close()
	default:
		return fmt.Errorf("unknown probe %q", p.Op)
	}
}

func seatbeltCompile(t *testing.T, policy *Policy, probes []seatbeltProbe) seatbeltRequest {
	t.Helper()
	profile, params, err := CompileSBPL(policy)
	if err != nil {
		t.Fatal(err)
	}
	return seatbeltRequest{Profile: profile, Params: params, Probes: probes}
}

func seatbeltRun(t *testing.T, req seatbeltRequest) {
	t.Helper()
	data, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestSeatbeltEnforceHelper$", "-test.count=1")
	cmd.Env = append(os.Environ(), seatbeltHelperEnv+"="+string(data))
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Seatbelt subprocess: %v\n%s", err, out)
	}
}

func seatbeltWriteFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
}

func seatbeltMkdir(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(path, 0700); err != nil {
		t.Fatal(err)
	}
}

func TestSeatbeltEnforceFiles(t *testing.T) {
	dir := t.TempDir()
	read, write, denied := filepath.Join(dir, "read"), filepath.Join(dir, "write"), filepath.Join(dir, "denied")
	for _, path := range []string{read, write, denied} {
		seatbeltWriteFile(t, path)
	}
	seatbeltRun(t, seatbeltCompile(t, &Policy{FS: []FSRule{
		{Path: read, Access: "r"},
		{Path: write, Access: "w"},
	}}, []seatbeltProbe{
		{"read", read, false},
		{"write", read, true},
		{"write", write, false},
		{"read", write, true},
		{"read", denied, true},
		{"write", denied, true},
	}))
}

func TestSeatbeltEnforceExec(t *testing.T) {
	for _, allowed := range []string{"/usr/bin/true", "/bin/echo"} {
		t.Run(filepath.Base(allowed), func(t *testing.T) {
			denied := "/bin/echo"
			if allowed == denied {
				denied = "/usr/bin/true"
			}
			seatbeltRun(t, seatbeltCompile(t, &Policy{FS: []FSRule{
				// Reading an executable must not itself permit execution.
				{Path: "/", Access: "r"},
				{Path: "/usr/lib", Access: "rx"},
				{Path: "/System/Library", Access: "rx"},
				{Path: allowed, Access: "x"},
			}}, []seatbeltProbe{
				{"exec", allowed, false},
				{"exec", denied, true},
			}))
		})
	}
}

// Darwin's sockaddr_un is short, so avoid the long per-test TMPDIR prefix.
func seatbeltSocketDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "lc-sb-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := os.RemoveAll(dir); err != nil {
			t.Error(err)
		}
	})
	canonical, err := filepath.EvalSymlinks(dir)
	if err != nil {
		t.Fatal(err)
	}
	return canonical
}

func seatbeltListen(t *testing.T, path string) {
	t.Helper()
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
}

func TestSeatbeltEnforceUnixConnect(t *testing.T) {
	dir := seatbeltSocketDir(t)
	allowedDir, neighborDir := filepath.Join(dir, "allowed"), filepath.Join(dir, "allowed-other")
	seatbeltMkdir(t, filepath.Join(allowedDir, "nested"))
	seatbeltMkdir(t, neighborDir)
	exact := filepath.Join(dir, "exact.sock")
	direct := filepath.Join(allowedDir, "direct.sock")
	descendant := filepath.Join(allowedDir, "nested", "deep.sock")
	neighbor := filepath.Join(neighborDir, "denied.sock")
	noRule := filepath.Join(dir, "no-rule.sock")
	for _, path := range []string{exact, direct, descendant, neighbor, noRule} {
		seatbeltListen(t, path)
	}
	file, descendantFile := filepath.Join(dir, "file"), filepath.Join(allowedDir, "file")
	seatbeltWriteFile(t, file)
	seatbeltWriteFile(t, descendantFile)
	for _, allowNet := range []bool{false, true} {
		t.Run(fmt.Sprintf("net-allow-%t", allowNet), func(t *testing.T) {
			seatbeltRun(t, seatbeltCompile(t, &Policy{
				FS: []FSRule{
					{Path: exact, Access: "u"},
					{Path: allowedDir, Access: "u"},
					{Path: file, Access: "u"},
				},
				Net: NetConfig{Allow: allowNet},
			}, []seatbeltProbe{
				{"connect", exact, false},
				{"connect", direct, false},
				{"connect", descendant, false},
				{"connect", neighbor, true},
				{"connect", noRule, true},
				{"read", file, true},
				{"write", file, true},
				{"read", descendantFile, true},
				{"write", descendantFile, true},
			}))
		})
	}
}

func TestSeatbeltEnforceUnixCreate(t *testing.T) {
	dir := seatbeltSocketDir(t)
	allowedDir, neighborDir := filepath.Join(dir, "allowed"), filepath.Join(dir, "allowed-other")
	seatbeltMkdir(t, filepath.Join(allowedDir, "nested"))
	seatbeltMkdir(t, neighborDir)
	existing := filepath.Join(allowedDir, "existing.sock")
	seatbeltListen(t, existing)
	seatbeltRun(t, seatbeltCompile(t, &Policy{FS: []FSRule{
		{Path: allowedDir, Access: "c"},
	}}, []seatbeltProbe{
		{"listen", filepath.Join(allowedDir, "direct.sock"), false},
		{"listen", filepath.Join(allowedDir, "nested", "deep.sock"), false},
		{"listen", filepath.Join(neighborDir, "denied.sock"), true},
		{"connect", existing, true},
	}))
}

func TestSeatbeltEnforceGlobSnapshot(t *testing.T) {
	dir := t.TempDir()
	matchedDir := filepath.Join(dir, "match-dir")
	seatbeltMkdir(t, filepath.Join(matchedDir, "nested"))
	file, descendant := filepath.Join(dir, "match-file"), filepath.Join(matchedDir, "nested", "file")
	seatbeltWriteFile(t, file)
	seatbeltWriteFile(t, descendant)
	newChild := filepath.Join(matchedDir, "new-child")
	futureFile := filepath.Join(dir, "match-future-file")
	futureDir := filepath.Join(dir, "match-future-dir")
	futureDescendant := filepath.Join(futureDir, "file")
	outside := filepath.Join(dir, "outside")
	req := seatbeltCompile(t, &Policy{FS: []FSRule{
		{Path: filepath.Join(dir, "match-*"), Access: "r"},
	}}, []seatbeltProbe{
		{"read", file, false},
		{"read", descendant, false},
		{"read", newChild, false},
		{"read", futureFile, true},
		{"read", futureDescendant, true},
		{"read", outside, true},
	})
	// Existing matched directories grant descendants, including new ones,
	// but new glob matches outside those directories must remain denied.
	seatbeltMkdir(t, futureDir)
	for _, path := range []string{newChild, futureFile, futureDescendant, outside} {
		seatbeltWriteFile(t, path)
	}
	seatbeltRun(t, req)
}
