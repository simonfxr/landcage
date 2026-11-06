//go:build linux

package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

func TestEnforceAllThreadsAndNoNewPrivs(t *testing.T) {
	feat, err := DetectFeatures()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	path := filepath.Join(t.TempDir(), "write-probe")
	if err := os.WriteFile(path, nil, 0600); err != nil {
		t.Fatal(err)
	}
	out := runEnforceHelperWithEnv(t, "threads-nnp", "LANDCAGE_TEST_THREAD_PATH="+path)
	if !strings.HasPrefix(out, "ENFORCED ") {
		t.Fatalf("thread enforcement failed: %s", out)
	}
	t.Logf("ABI %d: %s", feat.ABI, out)
}

// Pin several pre-existing threads before Enforce. Checking only threads
// created after enforcement would miss a failure to synchronize the ruleset
// or no_new_privs across the whole process.
func helperEnforceThreads() int {
	const count = 4
	ready := make(chan int, count)
	probe := make(chan struct{})
	results := make(chan error, count)
	path := os.Getenv("LANDCAGE_TEST_THREAD_PATH")
	for range count {
		go func() {
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			before, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
			ready <- before
			<-probe
			if err != nil {
				results <- fmt.Errorf("initial PR_GET_NO_NEW_PRIVS: %w", err)
				return
			}
			results <- probeThreadRestrictions(path)
		}()
	}
	inherited := 0
	for range count {
		if <-ready == 1 {
			inherited++
		}
	}
	if err := Enforce(&Policy{FS: []FSRule{{Path: "/", Access: "rx"}}, Net: NetConfig{Allow: true}}); err != nil {
		fmt.Fprintln(os.Stderr, "enforce:", err)
		return 2
	}
	close(probe)
	for range count {
		if err := <-results; err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 2
		}
	}
	// A surrounding sandbox may already set NNP. Report that explicitly:
	// no_new_privs cannot be reset to test its transition in that case.
	fmt.Printf("ENFORCED no_new_privs already set on %d/%d threads", inherited, count)
	return 0
}

func probeThreadRestrictions(path string) error {
	nnp, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil || nnp != 1 {
		return fmt.Errorf("thread %d: no_new_privs = %d, err = %v", unix.Gettid(), nnp, err)
	}
	fd, err := unix.Open(path, unix.O_WRONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Close(fd)
		return fmt.Errorf("thread %d: write permitted after read-only enforcement", unix.Gettid())
	}
	if !errors.Is(err, unix.EACCES) {
		return fmt.Errorf("thread %d: expected EACCES, got %w", unix.Gettid(), err)
	}
	return nil
}
