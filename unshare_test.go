package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/simonfxr/landcage/policy"
)

const (
	helperEnv       = "LANDCAGE_TEST_HELPER"
	helperSleepMode = "sleep"
)

// TestMain re-enters this binary as the payload of the integration test below.
func TestMain(m *testing.M) {
	if os.Getenv(helperEnv) == "network-fail-setup" {
		if isChild {
			os.Exit(1) // Simulate a child failing before reporting setup success.
		}
		main()
		os.Exit(0)
	}
	if os.Getenv(helperEnv) == "network" {
		networkHelper()
		os.Exit(0)
	}
	if os.Getenv(helperEnv) == helperSleepMode {
		time.Sleep(5 * time.Second)
		os.Exit(0)
	}
	os.Exit(m.Run())
}

func TestChildFD(t *testing.T) {
	t.Setenv(setupFDEnvKey, "7")
	if fd, err := childFD(setupFDEnvKey); err != nil || fd != 7 {
		t.Errorf("childFD = %d, %v; want 7, nil", fd, err)
	}

	tests := map[string]string{
		"unset":    "",
		"not a fd": "x",
		"reserved": "2",
		"negative": "-3",
	}
	for name, value := range tests {
		t.Run(name, func(t *testing.T) {
			t.Setenv(setupFDEnvKey, value)
			if _, err := childFD(setupFDEnvKey); err == nil {
				t.Errorf("childFD accepted %q", value)
			}
		})
	}
}

func TestReadChildStartup(t *testing.T) {
	want := childStartup{Policy: json.RawMessage(`{"name":"test"}`), Bin: "/bin/true"}
	payload, err := json.Marshal(want)
	if err != nil {
		t.Fatal(err)
	}

	fd := writePipe(t, payload)
	got, err := readChildStartup(fd)
	if err != nil {
		t.Fatal(err)
	}
	if string(got.Policy) != string(want.Policy) || got.Bin != want.Bin {
		t.Errorf("got %#v, want %#v", got, want)
	}
	if _, _, errno := syscall.RawSyscall(syscall.SYS_FCNTL, uintptr(fd), syscall.F_GETFD, 0); errno != syscall.EBADF {
		t.Errorf("startup pipe fd %d left open (errno %v)", fd, errno)
	}
}

func TestReadChildStartupRejectsBadPayloads(t *testing.T) {
	tests := map[string][]byte{
		"empty":          nil,
		"not json":       []byte("nope"),
		"missing policy": []byte(`{"bin":"/bin/true"}`),
	}
	for name, payload := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := readChildStartup(writePipe(t, payload)); err == nil {
				t.Errorf("readChildStartup accepted %q", payload)
			}
		})
	}

	t.Run("unreadable fd", func(t *testing.T) {
		if _, err := readChildStartup(9999); err == nil {
			t.Error("readChildStartup accepted an unopenable fd")
		}
	})
}

// writePipe returns a pipe's read end with payload written and the write end closed.
func writePipe(t *testing.T, payload []byte) int {
	t.Helper()
	var fds [2]int
	if err := syscall.Pipe(fds[:]); err != nil {
		t.Fatal(err)
	}
	if len(payload) > 0 {
		if _, err := syscall.Write(fds[1], payload); err != nil {
			t.Fatal(err)
		}
	}
	syscall.Close(fds[1])
	return fds[0]
}

func TestPayloadEnvStripsTransportVarAndRedactedSecrets(t *testing.T) {
	t.Setenv(publicPolicyEnvKey, `{"name":"outer"}`)
	t.Setenv("LANDCAGE_TEST_SECRET", "leak-canary")

	pol, err := policy.Parse([]byte(`{"name":"test","env":{
	  "LANDCAGE_TEST_SECRET": null,
	  "LANDCAGE_TEST_PATH": {"prepend": "/jail"}
	}}`))
	if err != nil {
		t.Fatal(err)
	}

	env, err := payloadEnv(pol)
	if err != nil {
		t.Fatal(err)
	}
	if v, ok := env[publicPolicyEnvKey]; ok {
		t.Errorf("policy transport variable leaked into the payload environment: %q", v)
	}
	if v, ok := env["LANDCAGE_TEST_SECRET"]; ok {
		t.Errorf("redacted secret still in the payload environment: %q", v)
	}
	if env["LANDCAGE_TEST_PATH"] != "/jail" {
		t.Errorf("policy env rules not applied: %q", env["LANDCAGE_TEST_PATH"])
	}
}

func TestPayloadEnvKeepsExplicitlySetTransportVar(t *testing.T) {
	t.Setenv(publicPolicyEnvKey, "stale")

	pol, err := policy.Parse([]byte(`{"name":"test","env":{"LANDCAGE_POLICY_JSON":"explicit"}}`))
	if err != nil {
		t.Fatal(err)
	}
	env, err := payloadEnv(pol)
	if err != nil {
		t.Fatal(err)
	}
	if env[publicPolicyEnvKey] != "explicit" {
		t.Errorf("policy-set %s = %q, want %q", publicPolicyEnvKey, env[publicPolicyEnvKey], "explicit")
	}
}

// TestReexecChildEnvironHasNoPolicy reads the environment block of the re-exec'd
// child of a real sandbox: it is the payload's parent and /proc keeps its
// exec-time block, so a policy passed through the environment would be visible.
func TestReexecChildEnvironHasNoPolicy(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a landcage binary and user namespaces")
	}
	bin := buildLandcageBinary(t)

	policyPath := filepath.Join(t.TempDir(), "policy.json")
	policyJSON := fmt.Sprintf(`{
	  "name": "environ-leak-test",
	  "unshare": {"user": true, "pid": true},
	  "env": {%q: %q, "LANDCAGE_TEST_SECRET": null},
	  "fs": [{"path": "/", "access": "rwxcd"}]
	}`, helperEnv, helperSleepMode)
	if err := os.WriteFile(policyPath, []byte(policyJSON), 0o600); err != nil {
		t.Fatal(err)
	}

	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(bin, "-p", policyPath, "--", self, "-test.run=^$")
	cmd.Env = append(os.Environ(), "LANDCAGE_TEST_SECRET=leak-canary")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		cmd.Process.Kill()
		cmd.Wait()
	}()

	reaper := waitForChild(cmd.Process.Pid)
	if reaper == 0 {
		t.Skip("no re-exec child, namespace isolation unavailable here")
	}
	environ := awaitReaperEnviron(t, reaper)
	for _, leaked := range []string{"leak-canary", "LANDCAGE_TEST_SECRET", publicPolicyEnvKey, "_LANDCAGE_POLICY"} {
		if strings.Contains(environ, leaked) {
			t.Errorf("%s readable from /proc/%d/environ:\n%s", leaked, reaper, environ)
		}
	}
}

// waitForChild returns the pid of a child of pid, or 0 if none appears. It scans
// /proc because the child belongs to the forking thread, not to the process.
func waitForChild(pid int) int {
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return 0
		}
		for _, entry := range entries {
			child, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			if parentOf(child) == pid {
				return child
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	return 0
}

func parentOf(pid int) int {
	status, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", pid))
	if err != nil {
		return 0
	}
	for line := range strings.Lines(string(status)) {
		if rest, ok := strings.CutPrefix(line, "PPid:"); ok {
			ppid, err := strconv.Atoi(strings.TrimSpace(rest))
			if err != nil {
				return 0
			}
			return ppid
		}
	}
	return 0
}

// awaitReaperEnviron waits for the re-exec'd child to run with the payload
// environment (the helper marker proves it) and returns that block.
func awaitReaperEnviron(t *testing.T, pid int) string {
	t.Helper()
	path := fmt.Sprintf("/proc/%d/environ", pid)
	deadline := time.Now().Add(3 * time.Second)
	var readErr error
	for time.Now().Before(deadline) {
		raw, err := os.ReadFile(path)
		if err != nil {
			readErr = err
		} else {
			environ := string(bytes.ReplaceAll(raw, []byte{0}, []byte{'\n'}))
			if strings.Contains(environ, helperEnv+"="+helperSleepMode) {
				return environ
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	if readErr != nil {
		t.Skipf("cannot read %s: %v", path, readErr)
	}
	t.Fatalf("re-exec'd child %d never ran with the payload environment", pid)
	return ""
}

func buildLandcageBinary(t *testing.T) string {
	t.Helper()
	goTool, err := exec.LookPath("go")
	if err != nil {
		t.Skip("no go toolchain to build landcage with")
	}
	bin := filepath.Join(t.TempDir(), "landcage")
	if out, err := exec.Command(goTool, "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("go build: %v: %s", err, out)
	}
	return bin
}
