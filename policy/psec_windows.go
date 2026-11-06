//go:build windows

package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/simonfxr/landcage/internal/winpsec"
)

// CompilePSEC translates only permissions representable without widening them.
// Paths and environment values must already be expanded by the existing policy
// loader. No filesystem grants (including the executable or system runtime) are
// implicit: callers must explicitly grant those paths, normally with --ro.
// Compilation rejects every reparse point and does not create directories or edit
// ACLs. The launcher must repeat path pinning through environment creation.
func CompilePSEC(p *Policy) (winpsec.Spec, error) {
	spec := winpsec.Spec{Network: winpsec.NetworkDeny}
	if p == nil {
		return spec, fmt.Errorf("windows PSEC: policy is nil")
	}
	if p.Unshare.Enabled() {
		return spec, fmt.Errorf("windows PSEC: Linux unshare namespaces are unsupported")
	}
	if p.Net.Allow || len(p.Net.Rules) != 0 {
		return spec, fmt.Errorf("windows PSEC: only network deny is supported; unrestricted and per-port policies cannot be represented")
	}
	// Empty IPC fields (including an omitted IPC object) request default
	// isolation, not unrestricted IPC. PSEC cannot enforce those scopes.
	if p.IPC == nil || p.IPC.AbstractUnix != "allow" || p.IPC.Signal != "allow" {
		return spec, fmt.Errorf("windows PSEC: IPC isolation is unsupported; ipc.abstract_unix and ipc.signal must both be explicitly \"allow\"")
	}
	for i := range p.FS {
		if err := compilePSECFS(&spec, &p.FS[i]); err != nil {
			return winpsec.Spec{}, fmt.Errorf("windows PSEC: fs rule %d (%s): %w", i, p.FS[i].Path, err)
		}
	}
	return spec, nil
}

func compilePSECFS(spec *winpsec.Spec, r *FSRule) error {
	if r.CreateDir != "" {
		return fmt.Errorf("create_dir is unsupported; pre-create the directory with appropriate Windows security")
	}
	// Compare sets, not character order; repeated access characters have the
	// same meaning as a single occurrence in other policy backends.
	readOnly := psecAccessEquals(r.Access, "rx") && !r.Refer && !r.IoctlDev
	readWrite := psecAccessEquals(r.Access, "rwxcdu") && r.Refer && r.IoctlDev
	if !readOnly && !readWrite {
		return fmt.Errorf("unsupported access: require rx without refer/ioctl_dev, or directory rwxcdu with refer=true and ioctl_dev=true")
	}
	if r.Path == "" && r.IgnoreMissing {
		return nil
	}
	paths, err := winpsec.ResolvePaths(r.Path)
	if err != nil {
		if r.IgnoreMissing && errors.Is(err, os.ErrNotExist) {
			return nil
		}
		return err
	}
	if len(paths) == 0 && !r.IgnoreMissing {
		return fmt.Errorf("glob matched no paths")
	}
	for _, path := range paths {
		if readWrite {
			if !path.IsDir {
				return fmt.Errorf("read-write files are unsupported; rwxcdu requires a directory")
			}
			spec.ReadWritePaths = append(spec.ReadWritePaths, path.Path)
		} else {
			spec.ReadOnlyPaths = append(spec.ReadOnlyPaths, path.Path)
		}
	}
	return nil
}

func psecAccessEquals(access, allowed string) bool {
	for _, ch := range allowed {
		if !strings.ContainsRune(access, ch) {
			return false
		}
	}
	return strings.Trim(access, allowed) == ""
}

func validatePSECPath(path string) error {
	return winpsec.ValidatePath(path)
}
