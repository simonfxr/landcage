//go:build !linux

package allthreads

import "syscall"

// AllThreadsSyscall3 is unavailable outside Linux.
//
//go:uintptrescapes
func AllThreadsSyscall3(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return 0, 0, syscall.ENOSYS
}

// AllThreadsSyscall6 is unavailable outside Linux.
//
//go:uintptrescapes
func AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
	return 0, 0, syscall.ENOSYS
}
