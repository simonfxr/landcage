// Package winpsec encodes PSEC 1.0 policies for the Windows process security
// environment API. Encoding is platform-independent; environment creation is Windows-only.
package winpsec

import (
	"fmt"
	"strings"
	"unicode/utf8"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/simonfxr/landcage/internal/winpsec/internal/layout"
)

// NetworkAction controls direct outbound traffic, not inbound or host-loopback access.
type NetworkAction uint8

const (
	// NetworkDeny is the default and grants no network capabilities.
	NetworkDeny NetworkAction = iota
	// NetworkAllowEgress permits direct outbound traffic through internetClient.
	// It does not represent unrestricted host networking.
	NetworkAllowEgress
)

// Spec contains explicit Windows filesystem paths. Callers must resolve and
// validate paths before encoding; this package does not expand or canonicalize them.
type Spec struct {
	ReadWritePaths []string
	ReadOnlyPaths  []string
	DeniedPaths    []string
	Network        NetworkAction
}

// All JOB_OBJECT_UILIMIT bits, including IME (0x100) and injection (0x200).
// Win32k itself remains enabled for USER32-dependent runtimes.
const uiRestrictions uint64 = 0x03ff

// Encode builds the versioned PSEC 1.0 FlatBuffer. It grants no capabilities
// beyond internetClient when explicitly requested, and never enables learning mode.
func Encode(spec Spec) ([]byte, error) {
	if spec.Network != NetworkDeny && spec.Network != NetworkAllowEgress {
		return nil, fmt.Errorf("unsupported network action %d", spec.Network)
	}
	for _, paths := range [][]string{spec.ReadWritePaths, spec.ReadOnlyPaths, spec.DeniedPaths} {
		for _, path := range paths {
			if path == "" || strings.ContainsRune(path, 0) || !utf8.ValidString(path) {
				return nil, fmt.Errorf("PSEC path must be nonempty UTF-8 without NUL: %q", path)
			}
		}
	}

	b := flatbuffers.NewBuilder(1024)
	rw := pathVector(b, spec.ReadWritePaths)
	ro := pathVector(b, spec.ReadOnlyPaths)
	deny := pathVector(b, spec.DeniedPaths)
	var capabilities flatbuffers.UOffsetT
	if spec.Network == NetworkAllowEgress {
		capabilities = b.CreateString("internetClient")
	}
	layout.EndpointPolicyStart(b)
	layout.EndpointPolicyAddDefaultAction(b, layout.FilterAction(spec.Network))
	egress := layout.EndpointPolicyEnd(b)
	layout.NetworkPolicyStart(b)
	layout.NetworkPolicyAddEgress(b, egress)
	network := layout.NetworkPolicyEnd(b)

	layout.ProcessSecurityEnvironmentStart(b)
	layout.ProcessSecurityEnvironmentAddCapabilities(b, capabilities)
	layout.ProcessSecurityEnvironmentAddUiRestrictions(b, uiRestrictions)
	layout.ProcessSecurityEnvironmentAddFsReadWrite(b, rw)
	layout.ProcessSecurityEnvironmentAddFsReadOnly(b, ro)
	layout.ProcessSecurityEnvironmentAddFsDeny(b, deny)
	layout.ProcessSecurityEnvironmentAddNetworkPolicy(b, network)
	version := layout.CreateSchemaVersion(b, 1, 0)
	layout.ProcessSecurityEnvironmentAddVersion(b, version)
	root := layout.ProcessSecurityEnvironmentEnd(b)
	layout.FinishProcessSecurityEnvironmentBuffer(b, root)
	return b.FinishedBytes(), nil
}

func pathVector(b *flatbuffers.Builder, paths []string) flatbuffers.UOffsetT {
	if len(paths) == 0 {
		return 0
	}
	offsets := make([]flatbuffers.UOffsetT, len(paths))
	for i, path := range paths {
		offsets[i] = b.CreateString(path)
	}
	b.StartVector(4, len(offsets), 4)
	for i := len(offsets) - 1; i >= 0; i-- {
		b.PrependUOffsetT(offsets[i])
	}
	return b.EndVector(len(offsets))
}
