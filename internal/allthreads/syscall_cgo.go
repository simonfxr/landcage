//go:build linux && cgo

// Package allthreads provides syscalls synchronized across all process threads.
package allthreads

import (
	"syscall"

	"kernel.org/pub/linux/libs/security/libcap/psx"
)

// AllThreadsSyscall3 executes a three-argument syscall on all Go and CGo threads.
//
//go:uintptrescapes
func AllThreadsSyscall3(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return psx.Syscall3(trap, a1, a2, a3)
}

// AllThreadsSyscall6 executes a six-argument syscall on all Go and CGo threads.
//
//go:uintptrescapes
func AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
	return psx.Syscall6(trap, a1, a2, a3, a4, a5, a6)
}
