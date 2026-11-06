//go:build windows

package policy

import (
	"fmt"
	"io"

	"github.com/simonfxr/landcage/internal/winpsec"
)

func platformDryRun(p *Policy, w io.Writer) error {
	// Translate first: unsupported policy must not produce a plausible plan.
	spec, err := CompilePSEC(p)
	if err != nil {
		return err
	}
	fmt.Fprintf(w, "Policy: %s\n", p.Name)
	if p.Description != "" {
		fmt.Fprintf(w, "Description: %s\n", p.Description)
	}
	PrintSandboxFeatures(w)
	fmt.Fprintln(w, "\nFilesystem grants (canonical paths):")
	for _, path := range spec.ReadOnlyPaths {
		fmt.Fprintf(w, "  RO (read + execute): %s\n", path)
	}
	for _, path := range spec.ReadWritePaths {
		fmt.Fprintf(w, "  RW (full read-write directory): %s\n", path)
	}
	if len(spec.ReadOnlyPaths)+len(spec.ReadWritePaths) == 0 {
		fmt.Fprintln(w, "  (none)")
	}
	fmt.Fprintln(w, "  No implicit grants or ACL changes; executable and runtime/system roots require explicit --ro.")
	fmt.Fprintln(w, "\nNetwork: deny (all IP networking; no network capabilities granted)")
	fmt.Fprintln(w, "Win32k: enabled")
	fmt.Fprintln(w, "UI restrictions: enabled separately through PSEC (not a Win32k disable)")
	fmt.Fprintln(w, "IPC: not Linux-scoped (abstract_unix=allow, signal=allow; restrictive scopes unsupported)")
	printDryRunEnvironment(p, w)
	return nil
}

// PrintSandboxFeatures queries baseline PSEC API support, not runtime enforcement.
// It does not create an environment, launch a process, or try another backend.
func PrintSandboxFeatures(w io.Writer) {
	printPSECSupport(w, winpsec.CheckSupport())
}

func printPSECSupport(w io.Writer, err error) {
	if err != nil {
		fmt.Fprintf(w, "Kernel features: Windows PSEC API support: unsupported/unavailable (%v)\n", err)
	} else {
		fmt.Fprintln(w, "Kernel features: Windows PSEC API support: available (baseline 1.0)")
	}
	fmt.Fprintln(w, "API support only; not runtime certification or MSYS/Git Bash compatibility validation.")
}
