package policy

import (
	"fmt"
	"io"
	"os"
	"strings"
)

// DryRun resolves all rules and prints what would be enforced, without
// actually applying the Landlock ruleset. All variable expansion must have
// been performed before calling DryRun (via template rendering at load time).
func DryRun(p *Policy, w io.Writer) error {
	feat, featErr := DetectFeatures()
	if featErr != nil {
		feat = LandlockFeatures{ABI: 0}
	}

	fmt.Fprintf(w, "Policy: %s\n", p.Name)
	if p.Description != "" {
		fmt.Fprintf(w, "Description: %s\n", p.Description)
	}
	fmt.Fprintf(w, "Kernel features: %s\n\n", feat.String())

	// Filesystem rules
	if len(p.FS) > 0 {
		fmt.Fprintf(w, "Filesystem rules:\n")
		for i, r := range p.FS {
			if r.Path == "" {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (empty path)\n", i)
					continue
				}
				return fmt.Errorf("fs rule %d: path is empty", i)
			}

			paths, err := resolvePath(r.Path)
			if err != nil {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (resolve error): %s\n", i, r.Path)
					continue
				}
				return fmt.Errorf("fs rule %d: %w", i, err)
			}

			if len(paths) == 0 {
				if r.IgnoreMissing {
					fmt.Fprintf(w, "  [%d] SKIP (no matches): %s\n", i, r.Path)
					continue
				}
				return fmt.Errorf("fs rule %d: no matches for %s", i, r.Path)
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
			fmt.Fprintf(w, "  [%d] port %d \u2192 %s\n", i, r.Port, r.Access)
		}
		fmt.Fprintln(w)
	} else {
		netNote := ""
		if !feat.SupportsNet() {
			netNote = fmt.Sprintf(" [WARN: not enforced, requires ABI >= 4, kernel has ABI %d]", feat.ABI)
		}
		fmt.Fprintf(w, "Network: deny (all TCP blocked)%s\n\n", netNote)
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
				fmt.Fprintf(w, "  %s = %q\n", name, *entry.Value)
			} else {
				var ops []string
				for _, p := range entry.Prepend {
					ops = append(ops, fmt.Sprintf("prepend %q", p))
				}
				for _, r := range entry.Remove {
					ops = append(ops, fmt.Sprintf("remove %q", r))
				}
				for _, a := range entry.Append {
					ops = append(ops, fmt.Sprintf("append %q", a))
				}
				fmt.Fprintf(w, "  %s: %s (sep=%q)\n", name, strings.Join(ops, ", "), entry.Sep)
			}
		}
	}

	return nil
}
