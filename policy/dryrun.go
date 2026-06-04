package policy

import (
	"fmt"
	"io"
	"os"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// DryRun resolves all rules and prints what would be enforced, without
// actually applying the Landlock ruleset.
func DryRun(p *Policy, w io.Writer) error {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		abi = 0
	}

	fmt.Fprintf(w, "Policy: %s\n", p.Name)
	if p.Description != "" {
		fmt.Fprintf(w, "Description: %s\n", p.Description)
	}
	fmt.Fprintf(w, "Landlock ABI: %d\n\n", abi)

	exp := NewExpander()

	// Filesystem rules
	if len(p.FS) > 0 {
		fmt.Fprintf(w, "Filesystem rules:\n")
		for i, r := range p.FS {
			ep, err := exp.Expand(r.Path)
			if err != nil {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (expand error): %s\n", i, r.Path)
					continue
				}
				return fmt.Errorf("fs rule %d: %w", i, err)
			}

			pathStr := ep.String()
			if pathStr == "" {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (empty path): %s\n", i, r.Path)
					continue
				}
				return fmt.Errorf("fs rule %d: path is empty after expansion", i)
			}

			paths, err := ep.Resolve()
			if err != nil {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (resolve error): %s → %s\n", i, r.Path, pathStr)
					continue
				}
				return fmt.Errorf("fs rule %d: %w", i, err)
			}

			if len(paths) == 0 {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (no matches): %s → %s\n", i, r.Path, pathStr)
					continue
				}
				return fmt.Errorf("fs rule %d: no matches for %s", i, pathStr)
			}

			for _, path := range paths {
				fi, err := os.Stat(path)
				if err != nil {
					if r.IgnoreMissing && os.IsNotExist(err) {
						fmt.Fprintf(w, "  [%d] SKIP (missing): %s\n", i, path)
						continue
					}
					return fmt.Errorf("fs rule %d: %w", i, err)
				}

				kind := "file"
				if fi.IsDir() {
					kind = "dir"
				}

				flags := r.Access
				if r.Refer {
					flags += " +refer"
				}
				if r.IoctlDev {
					flags += " +ioctl_dev"
				}

				fmt.Fprintf(w, "  [%d] %s (%s) → %s\n", i, path, kind, flags)
			}
		}
		fmt.Fprintln(w)
	}

	// Network rules
	if len(p.Net) > 0 {
		fmt.Fprintf(w, "Network rules:\n")
		for i, r := range p.Net {
			fmt.Fprintf(w, "  [%d] port %d → %s\n", i, r.Port, r.Access)
		}
		fmt.Fprintln(w)
	}

	// IPC
	fmt.Fprintf(w, "IPC:\n")
	abstractUnix := "best-effort deny"
	signal := "best-effort deny"
	if p.IPC != nil {
		if p.IPC.AbstractUnix != "" {
			abstractUnix = p.IPC.AbstractUnix
		}
		if p.IPC.Signal != "" {
			signal = p.IPC.Signal
		}
	}
	scopeSupported := "yes"
	if abi < 6 {
		scopeSupported = "no (requires ABI >= 6)"
	}
	fmt.Fprintf(w, "  abstract_unix: %s (kernel support: %s)\n", abstractUnix, scopeSupported)
	fmt.Fprintf(w, "  signal: %s (kernel support: %s)\n", signal, scopeSupported)

	return nil
}
