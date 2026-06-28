package policy

import (
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests exercise Landlock enforcement in a subprocess (enforcement is
// irreversible per-process). The test binary re-execs itself with a helper env.

const helperEnv = "LANDCAGE_TEST_ENFORCE_HELPER"

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(runHelper(mode))
	}
	os.Exit(m.Run())
}

func runHelper(mode string) int {
	pol := &Policy{
		Name: "enforce-test",
		FS: []FSRule{
			{Path: "/", Access: "rx"},
			{Path: "/dev", Access: "rw"},
			{Path: "/proc", Access: "r"},
			{Path: "/tmp", Access: "rwcd"},
		},
	}

	switch mode {
	case "net-deny":
		// net is zero value: Allow=false, Rules=nil → deny all
	case "net-allow":
		pol.Net.Allow = true
	case "net-port-80":
		pol.Net.Rules = []NetRule{{Port: 80, Access: "connect"}}
	case "unix-no-u":
		// /tmp has rwcd but no 'u' → connect to UNIX socket should be blocked
	case "unix-with-u":
		pol.FS[3] = FSRule{Path: "/tmp", Access: "rwcdu"}
	default:
		return 2
	}

	if err := Enforce(pol); err != nil {
		os.Stderr.WriteString("enforce: " + err.Error() + "\n")
		return 2
	}

	if strings.HasPrefix(mode, "unix-") {
		return helperUnixConnect()
	}
	return helperTCPConnect()
}

func helperTCPConnect() int {
	// Try TCP connect to localhost:1 (a port nothing listens on).
	// We only care whether the kernel returns EACCES (Landlock blocked) vs
	// ECONNREFUSED (Landlock allowed, but nothing there).
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 2*time.Second)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		os.Stdout.WriteString("CONNECTED")
		return 0
	}
	if isPermissionError(err) {
		os.Stdout.WriteString("BLOCKED")
		return 0
	}
	// Connection refused = kernel allowed the connect attempt (no Landlock block)
	os.Stdout.WriteString("REFUSED")
	return 0
}

func helperUnixConnect() int {
	sockPath := os.Getenv("LANDCAGE_TEST_UNIX_SOCK")
	conn, err := net.DialTimeout("unix", sockPath, 2*time.Second)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		os.Stdout.WriteString("CONNECTED")
		return 0
	}
	if isPermissionError(err) {
		os.Stdout.WriteString("BLOCKED")
		return 0
	}
	os.Stderr.WriteString("unexpected: " + err.Error() + "\n")
	os.Stdout.WriteString("ERROR")
	return 0
}

func isPermissionError(err error) bool {
	s := err.Error()
	return strings.Contains(s, "permission denied") ||
		strings.Contains(s, "operation not permitted")
}

func runEnforceHelper(t *testing.T, mode string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("helper %q exited %d: %s", mode, ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("helper %q: %v", mode, err)
	}
	return string(out)
}

func TestEnforceNetDeny(t *testing.T) {
	result := runEnforceHelper(t, "net-deny")
	if result != "BLOCKED" {
		t.Errorf("net=deny: expected BLOCKED, got %q", result)
	}
}

func TestEnforceNetAllow(t *testing.T) {
	result := runEnforceHelper(t, "net-allow")
	if result != "REFUSED" {
		t.Errorf("net=allow: expected REFUSED (connect allowed by kernel), got %q", result)
	}
}

func TestEnforceNetPort80(t *testing.T) {
	// Port 80 is allowed, port 1 is not.
	result := runEnforceHelper(t, "net-port-80")
	if result != "BLOCKED" {
		t.Errorf("net=[port 80]: connect to port 1 should be BLOCKED, got %q", result)
	}
}

func TestEnforceUnixNoU(t *testing.T) {
	sockPath := filepath.Join(t.TempDir(), "test.sock")
	ln := listenUnix(t, sockPath)
	defer ln.Close()

	result := runEnforceHelperWithEnv(t, "unix-no-u", "LANDCAGE_TEST_UNIX_SOCK="+sockPath)
	if result != "BLOCKED" {
		t.Errorf("unix without 'u': expected BLOCKED, got %q", result)
	}
}

func TestEnforceUnixWithU(t *testing.T) {
	sockPath := filepath.Join("/tmp", "landcage_test_u_"+strings.Replace(time.Now().Format("150405.000"), ".", "", 1)+".sock")
	ln := listenUnix(t, sockPath)
	defer ln.Close()
	defer os.Remove(sockPath)

	result := runEnforceHelperWithEnv(t, "unix-with-u", "LANDCAGE_TEST_UNIX_SOCK="+sockPath)
	if result != "CONNECTED" {
		t.Errorf("unix with 'u': expected CONNECTED, got %q", result)
	}
}

func listenUnix(t *testing.T, path string) net.Listener {
	t.Helper()
	ln, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	return ln
}

func runEnforceHelperWithEnv(t *testing.T, mode, extraEnv string) string {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^$")
	cmd.Env = append(os.Environ(), helperEnv+"="+mode, extraEnv)
	out, err := cmd.Output()
	if err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			t.Fatalf("helper %q exited %d: %s", mode, ee.ExitCode(), string(ee.Stderr))
		}
		t.Fatalf("helper %q: %v", mode, err)
	}
	return string(out)
}
