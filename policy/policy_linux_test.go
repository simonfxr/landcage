//go:build linux

package policy

import (
	"testing"

	llsys "github.com/landlock-lsm/go-landlock/landlock/syscall"
)

func TestFSAccessSetFileRejectsCreate(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rwc"}
	_, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err == nil {
		t.Error("expected error for 'c' on file")
	}
}

func TestFSAccessSetFileRejectsDelete(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "rd"}
	_, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err == nil {
		t.Error("expected error for 'd' on file")
	}
}

func TestFSAccessSetDirAllFlags(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rwxcdu", Refer: true, IoctlDev: true}
	access, err := fsAccessSet(r, true, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access == 0 {
		t.Error("expected non-zero access set")
	}
	if access&llsys.AccessFSResolveUnix == 0 {
		t.Error("RESOLVE_UNIX should be set for 'u' access")
	}
}

func TestFSAccessSetFileReadOnly(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "r"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSReadDir != 0 {
		t.Error("READ_DIR should not be set for file rule")
	}
	if access&llsys.AccessFSReadFile == 0 {
		t.Error("READ_FILE should be set for file rule")
	}
}

func TestFSAccessSetFileUnixSocketResolve(t *testing.T) {
	r := &FSRule{Path: "/tmp/sock", Access: "u"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access != llsys.AccessFSResolveUnix {
		t.Errorf("got access %d, want RESOLVE_UNIX %d", access, llsys.AccessFSResolveUnix)
	}

	// On ABI 8, 'u' alone results in zero access (silently dropped)
	access, err = fsAccessSet(r, false, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if access != 0 {
		t.Errorf("got access %d on ABI 8, want 0 (resolve_unix dropped)", access)
	}
}

func TestFSAccessSetTruncateDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp/f", Access: "w"}
	access, err := fsAccessSet(r, false, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSTruncate == 0 {
		t.Error("expected truncate to be set on ABI 9")
	}

	access, err = fsAccessSet(r, false, FeaturesForABI(2))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSTruncate != 0 {
		t.Error("expected truncate to NOT be set on ABI 2")
	}
}

func TestFSAccessSetResolveUnixDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rwu"}

	// On ABI 9+, resolve_unix should be present
	access, err := fsAccessSet(r, true, FeaturesForABI(9))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSResolveUnix == 0 {
		t.Error("expected resolve_unix to be set on ABI 9")
	}

	// On ABI 8, resolve_unix should be silently dropped
	access, err = fsAccessSet(r, true, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSResolveUnix != 0 {
		t.Error("expected resolve_unix to NOT be set on ABI 8")
	}
	// But write should still be present
	if access&llsys.AccessFSWriteFile == 0 {
		t.Error("expected write to still be set on ABI 8")
	}
}

func TestFSAccessSetReferDowngrade(t *testing.T) {
	r := &FSRule{Path: "/tmp", Access: "rw", Refer: true}

	// On ABI 2+, refer should be present
	access, err := fsAccessSet(r, true, FeaturesForABI(2))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSRefer == 0 {
		t.Error("expected refer to be set on ABI 2")
	}

	// On ABI 1, refer should be silently dropped
	access, err = fsAccessSet(r, true, FeaturesForABI(1))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSRefer != 0 {
		t.Error("expected refer to NOT be set on ABI 1")
	}
}

func TestFSAccessSetIoctlDevDowngrade(t *testing.T) {
	r := &FSRule{Path: "/dev/null", Access: "rw", IoctlDev: true}

	// On ABI 5+, ioctl_dev should be present
	access, err := fsAccessSet(r, false, FeaturesForABI(5))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSIoctlDev == 0 {
		t.Error("expected ioctl_dev to be set on ABI 5")
	}

	// On ABI 4, ioctl_dev should be silently dropped
	access, err = fsAccessSet(r, false, FeaturesForABI(4))
	if err != nil {
		t.Fatal(err)
	}
	if access&llsys.AccessFSIoctlDev != 0 {
		t.Error("expected ioctl_dev to NOT be set on ABI 4")
	}
}

func TestResolveScopesGranular(t *testing.T) {
	scoped, err := resolveScopes(&IPCConfig{AbstractUnix: "deny", Signal: "allow"}, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if scoped&llsys.ScopeAbstractUnixSocket == 0 {
		t.Error("expected ScopeAbstractUnixSocket to be set")
	}
	if scoped&llsys.ScopeSignal != 0 {
		t.Error("expected ScopeSignal to NOT be set")
	}

	scoped, err = resolveScopes(nil, FeaturesForABI(8))
	if err != nil {
		t.Fatal(err)
	}
	if scoped != llsys.ScopeAbstractUnixSocket|llsys.ScopeSignal {
		t.Errorf("expected both scopes set, got %d", scoped)
	}

	scoped, err = resolveScopes(nil, FeaturesForABI(5))
	if err != nil {
		t.Fatal(err)
	}
	if scoped != 0 {
		t.Errorf("expected 0 scopes on old kernel, got %d", scoped)
	}

	_, err = resolveScopes(&IPCConfig{Signal: "deny"}, FeaturesForABI(5))
	if err == nil {
		t.Error("expected error for hard deny on old kernel")
	}
}

func TestABI10UDPDetection(t *testing.T) {
	if FeaturesForABI(9).SupportsUDP() {
		t.Error("ABI 9 should not report UDP support")
	}
	if !FeaturesForABI(10).SupportsUDP() {
		t.Error("ABI 10 should report UDP support")
	}

	got9 := FeaturesForABI(9).MaxNetAccess()
	want9 := uint64(llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP)
	if uint64(got9) != want9 {
		t.Errorf("ABI 9 MaxNetAccess = %d, want TCP bits %d", got9, want9)
	}

	got10 := FeaturesForABI(10).MaxNetAccess()
	want10 := uint64(llsys.AccessNetBindTCP | llsys.AccessNetConnectTCP | llsys.AccessNetBindUDP | llsys.AccessNetConnectSendUDP)
	if uint64(got10) != want10 {
		t.Errorf("ABI 10 MaxNetAccess = %d, want TCP+UDP bits %d", got10, want10)
	}
}

func TestBuildNetRules(t *testing.T) {
	tcp := buildNetRules(&NetRule{Port: 443, Access: "connect"})
	if len(tcp) != 1 {
		t.Errorf("tcp connect: got %d rules, want 1", len(tcp))
	}
	udp := buildNetRules(&NetRule{Port: 53, Access: "connect", Proto: "udp"})
	if len(udp) != 1 {
		t.Errorf("udp connect: got %d rules, want 1", len(udp))
	}
	both := buildNetRules(&NetRule{Port: 53, Access: "connect+bind", Proto: "any"})
	if len(both) != 4 {
		t.Errorf("any connect+bind: got %d rules, want 4", len(both))
	}
}
