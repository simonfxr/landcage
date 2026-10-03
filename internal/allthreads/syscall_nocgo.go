//go:build linux && !cgo

// Package allthreads provides syscalls synchronized across all process threads.
package allthreads

import "syscall"

// AllThreadsSyscall3 executes a three-argument syscall on all Go threads.
//
//go:uintptrescapes
func AllThreadsSyscall3(trap, a1, a2, a3 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.AllThreadsSyscall(trap, a1, a2, a3)
}

// AllThreadsSyscall6 executes a six-argument syscall on all Go threads.
//
//go:uintptrescapes
func AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, syscall.Errno) {
	return syscall.AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6)
}
