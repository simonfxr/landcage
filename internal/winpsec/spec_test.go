package winpsec

import (
	"bytes"
	"errors"
	"reflect"
	"testing"

	flatbuffers "github.com/google/flatbuffers/go"
	"github.com/simonfxr/landcage/internal/winpsec/internal/layout"
)

func TestEncodeSchemaValues(t *testing.T) {
	spec := Spec{
		ReadWritePaths: []string{`C:\work`, `C:\café\文`},
		ReadOnlyPaths:  []string{`C:\Windows`, `C:\tools`},
		DeniedPaths:    []string{`C:\work\secret`, `C:\private`},
	}
	for _, mode := range []NetworkAction{NetworkDeny, NetworkAllowEgress} {
		spec.Network = mode
		blob, err := Encode(spec)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(blob[4:8], []byte("PSEC")) {
			t.Fatal("not an unprefixed PSEC FlatBuffer")
		}
		root := layout.GetRootAsProcessSecurityEnvironment(blob, 0)
		version := root.Version(nil)
		if version == nil || version.Major() != 1 || version.Minor() != 0 {
			t.Fatal("wrong schema version")
		}
		if root.DisallowWin32kSystemCalls() || root.UiRestrictions() != 0x03ff {
			t.Fatal("runtime-compatible Win32k/UI restrictions changed")
		}
		checkPaths(t, root.FsReadWriteLength(), root.FsReadWrite, spec.ReadWritePaths)
		checkPaths(t, root.FsReadOnlyLength(), root.FsReadOnly, spec.ReadOnlyPaths)
		checkPaths(t, root.FsDenyLength(), root.FsDeny, spec.DeniedPaths)
		if root.FsEnumerateLength() != 0 {
			t.Fatal("unexpected PSEC 1.1 enumerate paths")
		}
		network := root.NetworkPolicy(nil)
		if network == nil {
			t.Fatal("missing explicit network policy")
		}
		if network.Proxy(nil) != nil || network.Ingress(nil) != nil || len(network.AllowedAppcontainerPeer()) != 0 {
			t.Fatal("unexpected proxy, ingress, or peer policy")
		}
		egress := network.Egress(nil)
		if egress == nil || egress.AllowLength() != 0 || egress.DenyLength() != 0 {
			t.Fatal("unexpected egress rules")
		}
		wantAction := layout.FilterActiondeny
		wantCapabilities := ""
		if mode == NetworkAllowEgress {
			wantAction = layout.FilterActionallow
			wantCapabilities = "internetClient"
		}
		if egress.DefaultAction() != wantAction || string(root.Capabilities()) != wantCapabilities {
			t.Fatalf("network %d: action=%v capabilities=%q", mode, egress.DefaultAction(), root.Capabilities())
		}
		flags, err := requiredSupport(blob)
		if err != nil || flags != supportFileSystemDeny {
			t.Fatalf("deny paths must require native FS_DENY: 0x%x, %v", flags, err)
		}
		again, err := Encode(spec)
		if err != nil || !bytes.Equal(blob, again) {
			t.Fatal("encoding is not deterministic")
		}
	}
}

func checkPaths(t *testing.T, length int, get func(int) []byte, want []string) {
	t.Helper()
	got := make([]string, length)
	for i := range got {
		got[i] = string(get(i))
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("paths = %q, want %q", got, want)
	}
}

func TestEncodeZeroValueDeniesEgress(t *testing.T) {
	blob, err := Encode(Spec{})
	if err != nil {
		t.Fatal(err)
	}
	root := layout.GetRootAsProcessSecurityEnvironment(blob, 0)
	if len(root.Capabilities()) != 0 || root.NetworkPolicy(nil).Egress(nil).DefaultAction() != layout.FilterActiondeny {
		t.Fatal("zero value must deny egress without network capabilities")
	}
	if root.FsReadWriteLength() != 0 || root.FsReadOnlyLength() != 0 || root.FsDenyLength() != 0 {
		t.Fatal("zero value must grant no filesystem paths")
	}
	flags, err := requiredSupport(blob)
	if err != nil || flags != 0 {
		t.Fatalf("baseline requirements: 0x%x, %v", flags, err)
	}
}

func TestEncodeRejectsInvalidSpec(t *testing.T) {
	for _, spec := range []Spec{
		{Network: NetworkAction(2)},
		{Network: NetworkAction(255)},
		{ReadWritePaths: []string{""}},
		{ReadOnlyPaths: []string{"C:\\path\x00hidden"}},
		{DeniedPaths: []string{"C:\\\xff"}},
	} {
		if blob, err := Encode(spec); err == nil || blob != nil {
			t.Fatalf("invalid spec accepted: %#v", spec)
		}
	}
}

func TestRequiredSupportRejectsInvalidBuffers(t *testing.T) {
	valid, err := Encode(Spec{})
	if err != nil {
		t.Fatal(err)
	}
	badVersion := bytes.Clone(valid)
	layout.GetRootAsProcessSecurityEnvironment(badVersion, 0).Version(nil).MutateMinor(1)
	badRoot := bytes.Clone(valid)
	copy(badRoot, []byte{255, 255, 255, 127})
	missingVersion := flatbuffers.NewBuilder(32)
	layout.ProcessSecurityEnvironmentStart(missingVersion)
	root := layout.ProcessSecurityEnvironmentEnd(missingVersion)
	layout.FinishProcessSecurityEnvironmentBuffer(missingVersion, root)
	for _, blob := range [][]byte{
		nil, valid[:7], []byte("1234SBOX"), badVersion, badRoot, missingVersion.FinishedBytes(),
	} {
		if _, err := requiredSupport(blob); err == nil {
			t.Fatalf("invalid buffer accepted: %x", blob)
		}
	}
}

func TestRequiredSupportRejectsV11Fields(t *testing.T) {
	b := flatbuffers.NewBuilder(64)
	layout.IngressPolicyStart(b)
	ingress := layout.IngressPolicyEnd(b)
	layout.NetworkPolicyStart(b)
	layout.NetworkPolicyAddIngress(b, ingress)
	network := layout.NetworkPolicyEnd(b)
	layout.ProcessSecurityEnvironmentStart(b)
	layout.ProcessSecurityEnvironmentAddNetworkPolicy(b, network)
	version := layout.CreateSchemaVersion(b, 1, 0)
	layout.ProcessSecurityEnvironmentAddVersion(b, version)
	root := layout.ProcessSecurityEnvironmentEnd(b)
	layout.FinishProcessSecurityEnvironmentBuffer(b, root)
	if _, err := requiredSupport(b.FinishedBytes()); err == nil {
		t.Fatal("PSEC 1.1 ingress accepted with version 1.0")
	}
}

func TestCheckSupportFailsClosed(t *testing.T) {
	for _, tc := range []struct {
		available uint64
		required  uint64
		ok        bool
	}{
		{0, 0, true},
		{0, supportFileSystemDeny, false},
		{4, supportFileSystemDeny, false},
		{supportFileSystemDeny, supportFileSystemDeny, true},
		{^uint64(0), supportFileSystemDeny, true},
	} {
		err := checkSupport(tc.available, tc.required)
		if (err == nil) != tc.ok || (!tc.ok && !errors.Is(err, ErrUnsupported)) {
			t.Fatalf("support available=0x%x required=0x%x: %v", tc.available, tc.required, err)
		}
	}
}
