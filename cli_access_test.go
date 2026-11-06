package main

import (
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
	"golang.org/x/sys/unix"
)

// Re-exec the test to keep irreversible Landlock restrictions out of the
// parent. Build the rules through the same path as --rw, not hand-written JSON.
func TestCLIAccessProbe(t *testing.T) {
	mode := os.Getenv("LANDCAGE_TEST_CLI_ACCESS")
	if mode == "" {
		t.Skip("subprocess helper")
	}
	a := args{RO: []string{"/"}}
	if grant := os.Getenv("LANDCAGE_TEST_CLI_GRANT"); grant != "" {
		a.RW = []string{grant}
	}
	p, err := arg.NewParser(arg.Config{}, &a)
	if err != nil {
		t.Fatal(err)
	}
	if err := policy.Enforce(buildPolicy(&a, p)); err != nil {
		t.Fatal(err)
	}
	switch mode {
	case "socket":
		conn, dialErr := net.DialTimeout("unix", os.Getenv("LANDCAGE_TEST_CLI_TARGET"), time.Second)
		if conn != nil {
			conn.Close()
		}
		err = dialErr
	case "ioctl":
		err = probeDeviceIoctl()
		// /dev/null has no terminal ioctl: ENOTTY proves the request reached
		// the driver rather than being denied by Landlock.
		if errors.Is(err, unix.ENOTTY) {
			err = nil
		}
	default:
		t.Fatalf("unknown probe %q", mode)
	}
	if os.Getenv("LANDCAGE_TEST_CLI_DENY") == "1" {
		if !errors.Is(err, unix.EACCES) {
			t.Fatalf("want Landlock denial, got %v", err)
		}
	} else if err != nil {
		t.Fatalf("granted operation failed: %v", err)
	}
}

func probeDeviceIoctl() error {
	fd, err := unix.Open("/dev/null", unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	_, err = unix.IoctlGetWinsize(fd, unix.TIOCGWINSZ)
	return err
}

func TestCLIRWEnforcement(t *testing.T) {
	feat, err := policy.DetectFeatures()
	if err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	t.Run("socket", func(t *testing.T) {
		if !feat.SupportsResolveUnix() {
			t.Skip("requires Landlock ABI >= 9")
		}
		dir := t.TempDir()
		path := filepath.Join(dir, "s")
		ln, err := net.Listen("unix", path)
		if err != nil {
			t.Fatal(err)
		}
		defer ln.Close()
		conn, err := net.DialTimeout("unix", path, time.Second)
		if err != nil {
			t.Skipf("outer sandbox prevents socket connection: %v", err)
		}
		conn.Close()
		for name, grant := range map[string]string{"denied": "", "directory": dir, "exact": path} {
			t.Run(name, func(t *testing.T) {
				runCLIAccessProbe(t, "socket", grant, path)
			})
		}
	})
	t.Run("ioctl", func(t *testing.T) {
		if !feat.SupportsIoctlDev() {
			t.Skip("requires Landlock ABI >= 5")
		}
		if err := probeDeviceIoctl(); !errors.Is(err, unix.ENOTTY) {
			t.Skipf("device ioctl probe unavailable outside sandbox: %v", err)
		}
		for name, grant := range map[string]string{"denied": "", "directory": "/dev", "exact": "/dev/null"} {
			t.Run(name, func(t *testing.T) {
				runCLIAccessProbe(t, "ioctl", grant, "/dev/null")
			})
		}
	})
}

func runCLIAccessProbe(t *testing.T, mode, grant, target string) {
	t.Helper()
	deny := "0"
	if grant == "" {
		deny = "1"
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCLIAccessProbe$")
	cmd.Env = append(os.Environ(),
		"LANDCAGE_TEST_CLI_ACCESS="+mode,
		"LANDCAGE_TEST_CLI_GRANT="+grant,
		"LANDCAGE_TEST_CLI_TARGET="+target,
		"LANDCAGE_TEST_CLI_DENY="+deny,
	)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe: %v\n%s", err, out)
	}
}
