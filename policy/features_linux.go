//go:build linux

package policy

import (
	"fmt"

	ll "github.com/landlock-lsm/go-landlock/landlock"
	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

// DetectFeatures queries the kernel for Landlock support.
func DetectFeatures() (LandlockFeatures, error) {
	abi, err := llsys.LandlockGetABIVersion()
	if err != nil {
		return LandlockFeatures{}, fmt.Errorf("landlock not available: %w", err)
	}
	if abi < 1 {
		return LandlockFeatures{}, fmt.Errorf("landlock ABI version %d not usable", abi)
	}
	return LandlockFeatures{ABI: abi}, nil
}

// ---- Access-set constructors ----

// MaxFSAccess returns the maximum AccessFSSet supported at this ABI level.
//
// Bitmask mapping:
//
//	V1: bits 0-12 (13 flags) — execute through make_sym
//	V2: bits 0-13 (14 flags) — adds refer
//	V3: bits 0-14 (15 flags) — adds truncate
//	V5: bits 0-15 (16 flags) — adds ioctl_dev
//	V9: bits 0-16 (17 flags) — adds resolve_unix
//	V10, V11: unchanged filesystem rights
func (f LandlockFeatures) MaxFSAccess() ll.AccessFSSet {
	switch {
	case f.ABI >= 9:
		return ll.AccessFSSet((1 << 17) - 1)
	case f.ABI >= 5:
		return ll.AccessFSSet((1 << 16) - 1)
	case f.ABI >= 3:
		return ll.AccessFSSet((1 << 15) - 1)
	case f.ABI >= 2:
		return ll.AccessFSSet((1 << 14) - 1)
	default: // ABI 1
		return ll.AccessFSSet((1 << 13) - 1)
	}
}

// MaxNetAccess returns the AccessNetSet landcage handles when net is restricted.
// TCP bind/connect are always included (ABI 4+). UDP bind/connect-send are
// included on ABI 10+ so unspecified UDP is denied by default, matching TCP.
func (f LandlockFeatures) MaxNetAccess() ll.AccessNetSet {
	access := ll.AccessNetSet(llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP)
	if f.SupportsUDP() {
		access |= ll.AccessNetSet(llsys.AccessNetBindUDP | llsys.AccessNetConnectSendUDP)
	}
	return access
}

// ---- Validation ----

// minABIForFSAccess maps Landlock FS access flags to their minimum kernel ABI.
//
// Only flags introduced after V1 are listed. All V1 flags (execute, write_file,
// read_file, read_dir, remove_dir, remove_file, make_char, make_dir, make_reg,
// make_sock, make_fifo, make_block, make_sym) have an implicit min ABI of 1 and
// therefore always pass validation when Landlock is available.
var minABIForFSAccess = map[ll.AccessFSSet]int{
	llsys.AccessFSRefer:       2,
	llsys.AccessFSTruncate:    3,
	llsys.AccessFSIoctlDev:    5,
	llsys.AccessFSResolveUnix: 9,
}

// ValidateFSAccess checks whether the kernel supports all FS access flags
// requested by the rule. Returns a slice of human-readable descriptions for
// any unsupported flags, or nil if all flags are supported by the kernel.
//
// Syntactic errors (e.g., "c" on a file) are not caught here — they are
// deferred to fsAccessSet during enforcement, which produces better
// context-specific messages.
func (f LandlockFeatures) ValidateFSAccess(rule *FSRule) (unsupported []string) {
	// Use dir=true for widest flag coverage; syntactic enforcement
	// ("c"/"d" on files) happens in fsAccessSet during enforcement.
	access, err := fsAccessSet(rule, true, f)
	if err != nil {
		return nil // syntactic errors surface during enforcement
	}

	var missing []string
	for flag, minABI := range minABIForFSAccess {
		if access&flag != 0 && f.ABI < minABI {
			name := fsAccessFlagName(flag)
			missing = append(missing,
				fmt.Sprintf("%s (requires ABI >= %d, kernel has ABI %d)", name, minABI, f.ABI))
		}
	}
	return missing
}

// fsAccessFlagName returns a human-readable name for an AccessFSSet flag.
func fsAccessFlagName(flag ll.AccessFSSet) string {
	switch flag {
	case llsys.AccessFSRefer:
		return "refer"
	case llsys.AccessFSTruncate:
		return "truncate"
	case llsys.AccessFSIoctlDev:
		return "ioctl_dev"
	case llsys.AccessFSResolveUnix:
		return "resolve_unix"
	default:
		return fmt.Sprintf("flag(%d)", flag)
	}
}
