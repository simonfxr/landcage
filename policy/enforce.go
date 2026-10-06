package policy

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"syscall"
)

// validatePolicyFeatures checks that the policy does not request features
// the current kernel cannot provide. For FS access flags, unsupported flags
// are silently downgraded (dropped) by fsAccessSet, so we only emit a warning.
// Network and IPC hard-deny still error because there is no safe downgrade.
func validatePolicyFeatures(p *Policy, feat LandlockFeatures) error {
	for i, r := range p.FS {
		unsupported := feat.ValidateFSAccess(&r)
		if len(unsupported) > 0 {
			fmt.Fprintf(os.Stderr, "landcage: warning: fs rule %d (%s): downgrading unsupported access flags on kernel ABI %d: %s\n",
				i, r.Path, feat.ABI, strings.Join(unsupported, "; "))
		}
	}

	if err := feat.ValidateNet(&p.Net); err != nil {
		return err
	}
	if !p.Net.Allow && !feat.SupportsNet() {
		fmt.Fprintf(os.Stderr, "landcage: warning: network unrestricted on kernel ABI %d (TCP restrictions require ABI >= 4 / Linux >= 6.7)\n", feat.ABI)
	} else if !p.Net.Allow && !feat.SupportsUDP() {
		fmt.Fprintf(os.Stderr, "landcage: warning: UDP unrestricted on kernel ABI %d (requires ABI >= 10 / Linux >= 7.2)\n", feat.ABI)
	}

	if err := feat.ValidateIPC(p.IPC); err != nil {
		return err
	}

	return nil
}

type ipcMode int

const (
	ipcIncludeScopes ipcMode = iota
	ipcExcludeScopes
	ipcHardDenyUnavailable
)

// resolveIPC determines how to handle IPC scopes.
// Exists alongside resolveScopes only to support TestResolveIPC — the production
// code path uses resolveScopes, which returns the actual ScopedSet bitmask.
// Keep both in sync if IPC logic changes.
func resolveIPC(ipc *IPCConfig, feat LandlockFeatures) ipcMode {
	abstractUnix := ""
	signal := ""
	if ipc != nil {
		abstractUnix = ipc.AbstractUnix
		signal = ipc.Signal
	}

	if abstractUnix == "allow" && signal == "allow" {
		return ipcExcludeScopes
	}
	if !feat.SupportsScoped() {
		if abstractUnix == "deny" || signal == "deny" {
			return ipcHardDenyUnavailable
		}
		return ipcExcludeScopes
	}
	return ipcIncludeScopes
}

// fsRuleError reports access flags that are invalid for this file type.
// 'c' and 'd' are directory operations, on Landlock and on Seatbelt.
func fsRuleError(r *FSRule, isDir bool) error {
	if isDir {
		return nil
	}
	for _, ch := range r.Access {
		switch ch {
		case 'c':
			return fmt.Errorf("'c' (create) access is invalid on files")
		case 'd':
			return fmt.Errorf("'d' (delete) access is invalid on files")
		}
	}
	return nil
}

func isPathError(err error) bool {
	if os.IsNotExist(err) {
		return true
	}
	var errno syscall.Errno
	if errors.As(err, &errno) && errno == syscall.ENOTDIR {
		return true
	}
	return false
}
