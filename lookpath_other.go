//go:build !windows

package main

import "os/exec"

func resolveExecutable(name string) (string, error) {
	return exec.LookPath(name)
}
