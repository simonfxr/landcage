package winpsec

import (
	"errors"
	"fmt"

	"github.com/simonfxr/landcage/internal/winpsec/internal/layout"
)

// ErrUnsupported means the host cannot provide the requested PSEC policy.
var ErrUnsupported = errors.New("Windows process security environments unsupported")

// PSE_SUPPORT_FS_DENY, as declared by the official processmodel contract.
const supportFileSystemDeny uint64 = 0x0000000000000001

// Inspect only the contract requirements; Windows validates the complete buffer.
// Generated FlatBuffers accessors are not bounds-checked parsers.
func requiredSupport(blob []byte) (flags uint64, err error) {
	defer func() {
		if recover() != nil {
			flags = 0
			err = errors.New("invalid PSEC buffer")
		}
	}()
	if len(blob) < 8 || !layout.ProcessSecurityEnvironmentBufferHasIdentifier(blob) {
		return 0, errors.New("invalid PSEC file identifier")
	}
	root := layout.GetRootAsProcessSecurityEnvironment(blob, 0)
	version := root.Version(nil)
	if version == nil || version.Major() != 1 || version.Minor() != 0 {
		return 0, errors.New("only PSEC version 1.0 is supported")
	}
	if root.FsEnumerateLength() != 0 {
		return 0, errors.New("enumeration-only paths require PSEC 1.1")
	}
	network := root.NetworkPolicy(nil)
	if network != nil && network.Ingress(nil) != nil {
		return 0, errors.New("ingress policy requires PSEC 1.1")
	}
	if root.FsDenyLength() != 0 {
		flags |= supportFileSystemDeny
	}
	return flags, nil
}

func checkSupport(available, required uint64) error {
	if available&required != required {
		return fmt.Errorf("%w: missing PSEC support bits 0x%x", ErrUnsupported, required & ^available)
	}
	return nil
}
