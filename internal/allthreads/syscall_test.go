//go:build linux

package allthreads

import (
	"os"
	"syscall"
	"testing"
)

func TestAllThreadsSyscalls(t *testing.T) {
	for _, tc := range []struct {
		name string
		call func(uintptr, uintptr, uintptr, uintptr) (uintptr, uintptr, syscall.Errno)
	}{
		{"three arguments", AllThreadsSyscall3},
		{"six arguments", func(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
			return AllThreadsSyscall6(trap, a1, a2, a3, 0, 0, 0)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pid, _, errno := tc.call(syscall.SYS_GETPID, 0, 0, 0)
			if errno != 0 || pid != uintptr(os.Getpid()) {
				t.Fatalf("getpid = %d, errno = %v; want %d", pid, errno, os.Getpid())
			}
			// An invalid prctl operation exercises argument/error forwarding
			// without changing the test process's security state.
			_, _, errno = tc.call(syscall.SYS_PRCTL, ^uintptr(0), 0, 0)
			if errno != syscall.EINVAL {
				t.Fatalf("invalid prctl errno = %v, want EINVAL", errno)
			}
		})
	}
}
