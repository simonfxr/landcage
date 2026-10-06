//go:build darwin && cgo

package main

import (
	"fmt"
	"os"
	"syscall"

	"github.com/simonfxr/landcage/policy"
)

// runSandboxed creates policy directories, applies the Seatbelt profile in
// this process, and execs bin. There is no pid namespace and no reaper.
// The seatbelt label survives exec.
func runSandboxed(pol *policy.Policy, env policy.Environ, bin string, cmd []string) {
	if pol.Unshare.Enabled() {
		fmt.Fprintf(os.Stderr, "landcage: warning: unshare is not supported on darwin; continuing without namespaces\n")
	}
	scrubDYLD(pol, env)

	if err := policy.CreatePolicyDirs(pol); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}
	profile, params, err := policy.CompileSBPL(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}
	if err := policy.Apply(profile, params); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: %v\n", err)
		os.Exit(1)
	}

	argv := env.ToSlice()
	if err := syscall.Exec(bin, cmd, argv); err != nil {
		fmt.Fprintf(os.Stderr, "landcage: exec: %v\n", err)
		os.Exit(126)
	}
}
