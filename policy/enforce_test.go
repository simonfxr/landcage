package policy

import (
	"net"
	"os"
	"os/exec"
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
	default:
		return 2
	}

	if err := Enforce(pol); err != nil {
		os.Stderr.WriteString("enforce: " + err.Error() + "\n")
		return 2
	}

	// Try TCP connect to localhost:1 (a port nothing listens on).
	// We only care whether the kernel returns EACCES (Landlock blocked) vs
	// ECONNREFUSED (Landlock allowed, but nothing there).
	conn, err := net.DialTimeout("tcp", "127.0.0.1:1", 2*time.Second)
	if conn != nil {
		conn.Close()
	}
	if err == nil {
		// Unexpected success
		os.Stdout.WriteString("CONNECTED")
		return 0
	}
	if strings.Contains(err.Error(), "permission denied") ||
		strings.Contains(err.Error(), "operation not permitted") {
		os.Stdout.WriteString("BLOCKED")
		return 0
	}
	// Connection refused = kernel allowed the connect attempt (no Landlock block)
	os.Stdout.WriteString("REFUSED")
	return 0
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
