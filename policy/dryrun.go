package policy

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// DryRun resolves all rules and prints what would be enforced, without
// actually applying the Landlock ruleset.
func DryRun(p *Policy, opts *Options, w io.Writer) error {
	feat, featErr := DetectFeatures()
	if featErr != nil {
		feat = LandlockFeatures{ABI: 0}
	}

	fmt.Fprintf(w, "Policy: %s\n", p.Name)
	if p.Description != "" {
		fmt.Fprintf(w, "Description: %s\n", p.Description)
	}
	fmt.Fprintf(w, "Kernel features: %s\n\n", feat.String())

	exp := NewExpander(opts)

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

			// Compute warning once per rule, not per resolved path.
			warning := ""
			if unsupported := feat.ValidateFSAccess(&r); len(unsupported) > 0 {
				warning = fmt.Sprintf("  [WARN] unsupported: %s", strings.Join(unsupported, "; "))
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

				// Show downgrade notes for flags silently omitted due to kernel ABI.
				note := ""
				if strings.ContainsRune(r.Access, 'w') && !feat.SupportsTruncate() {
					note = fmt.Sprintf(" [note: truncate unavailable on ABI %d]", feat.ABI)
				}

				fmt.Fprintf(w, "  [%d] %s (%s) → %s%s%s\n", i, path, kind, flags, warning, note)
			}
		}
		fmt.Fprintln(w)
	}

	// Network rules
	if p.Net.Allow {
		fmt.Fprintf(w, "Network: allow (unrestricted)\n\n")
	} else if len(p.Net.Rules) > 0 {
		netWarn := ""
		if !feat.SupportsNet() {
			netWarn = fmt.Sprintf(" [WARN: network requires ABI >= 4, kernel has ABI %d]", feat.ABI)
		}
		fmt.Fprintf(w, "Network rules:%s\n", netWarn)
		for i, r := range p.Net.Rules {
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
	if !feat.SupportsScoped() {
		scopeSupported = fmt.Sprintf("no (requires ABI >= 6, kernel has ABI %d)", feat.ABI)
	}
	auWarn := ""
	sigWarn := ""
	if !feat.SupportsScoped() && p.IPC != nil {
		if p.IPC.AbstractUnix == "deny" {
			auWarn = fmt.Sprintf(" [WARN: enforcement would fail on kernel ABI %d]", feat.ABI)
		}
		if p.IPC.Signal == "deny" {
			sigWarn = fmt.Sprintf(" [WARN: enforcement would fail on kernel ABI %d]", feat.ABI)
		}
	}
	fmt.Fprintf(w, "  abstract_unix: %s (kernel support: %s)%s\n", abstractUnix, scopeSupported, auWarn)
	fmt.Fprintf(w, "  signal: %s (kernel support: %s)%s\n", signal, scopeSupported, sigWarn)

	// Environment
	if len(p.Env) > 0 {
		fmt.Fprintf(w, "\nEnvironment:\n")
		for name, entry := range p.Env {
			if entry.Unset {
				fmt.Fprintf(w, "  %s: UNSET\n", name)
			} else if entry.Value != nil {
				expanded, err := exp.Expand(*entry.Value)
				if err != nil {
					return fmt.Errorf("env %s: %w", name, err)
				}
				fmt.Fprintf(w, "  %s = %q\n", name, expanded.String())
			} else {
				// Path operation
				var ops []string
				for _, p := range entry.Prepend {
					expanded, _ := exp.Expand(p)
					ops = append(ops, fmt.Sprintf("prepend %q", expanded.String()))
				}
				for _, r := range entry.Remove {
					expanded, _ := exp.Expand(r)
					ops = append(ops, fmt.Sprintf("remove %q", expanded.String()))
				}
				for _, a := range entry.Append {
					expanded, _ := exp.Expand(a)
					ops = append(ops, fmt.Sprintf("append %q", expanded.String()))
				}
				fmt.Fprintf(w, "  %s: %s (sep=%q)\n", name, strings.Join(ops, ", "), entry.Sep)
			}
		}
	}

	return nil
}
