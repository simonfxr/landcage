//go:build windows

package main

import (
	"fmt"
	"os"

	"github.com/simonfxr/landcage/internal/winpsec"
	"github.com/simonfxr/landcage/policy"
)

func runSandboxed(pol *policy.Policy, env policy.Environ, bin string, cmd []string) {
	spec, err := policy.CompilePSEC(pol)
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: refusing to start Windows sandbox: %v\n", err)
		os.Exit(1)
	}
	code, err := winpsec.Run(spec, bin, cmd, env.ToSlice())
	if err != nil {
		fmt.Fprintf(os.Stderr, "landcage: Windows PSEC sandbox failed (no unsandboxed fallback): %v\n", err)
		fmt.Fprintln(os.Stderr, "landcage: the executable and runtime/system roots must be explicitly granted with --ro; no filesystem grants or ACL changes are added automatically")
		if code != 0 {
			os.Exit(int(code))
		}
		os.Exit(1)
	}
	os.Exit(int(code))
}
