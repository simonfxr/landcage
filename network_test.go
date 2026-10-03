package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"

	"github.com/alexflint/go-arg"
	"github.com/simonfxr/landcage/policy"
)

func TestCLINetworkMode(t *testing.T) {
	for _, mode := range []string{"", "host", "none", "isolated", "proxy", "invalid"} {
		t.Run(mode, func(t *testing.T) {
			var a args
			p, err := arg.NewParser(arg.Config{}, &a)
			if err != nil {
				t.Fatal(err)
			}
			var argv []string
			if mode != "" {
				argv = []string{"--net", mode}
			}
			err = p.Parse(argv)
			if mode == "proxy" || mode == "invalid" {
				if err == nil || !strings.Contains(err.Error(), "host, none, or isolated") {
					t.Fatalf("expected invalid mode error, got %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			want := mode
			if want == "" {
				want = "host"
			}
			if a.Net != networkMode(want) {
				t.Fatalf("mode = %q, want %q", a.Net, want)
			}
		})
	}
}

func TestNetworkNamespaceAttrs(t *testing.T) {
	for _, mode := range []networkMode{networkHost, networkNone, networkIsolated} {
		for _, existing := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/existing=%t", mode, existing), func(t *testing.T) {
				var cfg *policy.UnshareConfig
				wantFlags := uintptr(0)
				if existing {
					cfg = &policy.UnshareConfig{User: true, PID: true, Cgroup: true, MountProc: true}
					wantFlags = syscall.CLONE_NEWUSER | syscall.CLONE_NEWPID | syscall.CLONE_NEWCGROUP | syscall.CLONE_NEWNS
				}
				if mode.private() {
					wantFlags |= syscall.CLONE_NEWUSER | syscall.CLONE_NEWNET
				}
				attrs := namespaceAttrs(cfg, mode)
				if attrs.Cloneflags != wantFlags {
					t.Fatalf("clone flags = %#x, want %#x", attrs.Cloneflags, wantFlags)
				}
				if mode.private() {
					if len(attrs.UidMappings) != 1 || attrs.UidMappings[0].ContainerID != os.Geteuid() ||
						len(attrs.GidMappings) != 1 || attrs.GidMappings[0].ContainerID != os.Getegid() {
						t.Fatalf("missing current-user mappings: %+v", attrs)
					}
				}
				netAdmin := false
				for _, cap := range attrs.AmbientCaps {
					netAdmin = netAdmin || cap == capNetAdmin
				}
				if netAdmin != (mode == networkIsolated) {
					t.Fatalf("CAP_NET_ADMIN = %t for %s", netAdmin, mode)
				}
			})
		}
	}
}

type networkReport struct {
	Namespace  string
	Interfaces []string
	LoopbackUp bool
	IPv4       bool
	TCPWorks   bool
	Caps       []string
}

// networkHelper runs as a sandbox payload, so interface flags and connections
// are observed in the namespace that the actual command receives.
func networkHelper() {
	var report networkReport
	var err error
	report.Namespace, err = os.Readlink("/proc/self/ns/net")
	if err != nil {
		panic(err)
	}
	interfaces, err := net.Interfaces()
	if err != nil {
		panic(err)
	}
	for _, iface := range interfaces {
		report.Interfaces = append(report.Interfaces, iface.Name)
		if iface.Name != "lo" {
			continue
		}
		report.LoopbackUp = iface.Flags&net.FlagUp != 0
		addrs, err := iface.Addrs()
		if err != nil {
			panic(err)
		}
		for _, addr := range addrs {
			report.IPv4 = report.IPv4 || addr.String() == "127.0.0.1/8"
		}
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err == nil {
		// The kernel completes the local handshake without a userspace accept.
		conn, err := net.Dial("tcp4", listener.Addr().String())
		report.TCPWorks = err == nil
		if conn != nil {
			conn.Close()
		}
		listener.Close()
	}
	status, err := os.ReadFile("/proc/self/status")
	if err != nil {
		panic(err)
	}
	for _, line := range strings.Split(string(status), "\n") {
		if strings.HasPrefix(line, "Cap") && !strings.HasPrefix(line, "CapBnd:") {
			report.Caps = append(report.Caps, line)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(report); err != nil {
		panic(err)
	}
}

func TestNetworkModes(t *testing.T) {
	if testing.Short() {
		t.Skip("needs a landcage binary and user namespaces")
	}
	if _, err := policy.DetectFeatures(); err != nil {
		t.Skipf("Landlock unavailable: %v", err)
	}
	bin := buildLandcageBinary(t)
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	hostNS, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}

	// Probe clone directly so unsupported environments still verify fail-closed
	// behavior rather than silently skipping a broken implementation.
	probe := exec.Command(self, "-test.run=^$")
	probe.Env = append(os.Environ(), helperEnv+"=")
	probe.SysProcAttr = namespaceAttrs(nil, networkNone)
	probeErr := probe.Run()
	if probeErr != nil && !isNamespaceError(probeErr) {
		t.Fatalf("namespace probe: %v", probeErr)
	}

	for _, mode := range []string{"", "host", "none", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			argv := []string{"--policy-json-from-env"}
			if mode != "" {
				argv = append(argv, "--net", mode)
			}
			argv = append(argv, "--", self, "-test.run=^$")
			cmd := exec.Command(bin, argv...)
			cmd.Env = append(os.Environ(),
				helperEnv+"=network",
				publicPolicyEnvKey+`={"name":"network-test","fs":[{"path":"/","access":"rx"}],"net":"allow"}`,
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			private := mode == "none" || mode == "isolated"
			if private && probeErr != nil {
				if err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "refusing host network fallback") {
					t.Fatalf("expected fail-closed without payload execution: err=%v stdout=%s stderr=%s", err, &stdout, &stderr)
				}
				t.Logf("private namespaces unavailable; verified fail-closed: %v", probeErr)
				return
			}
			if err != nil {
				t.Fatalf("payload: %v\n%s", err, &stderr)
			}
			var report networkReport
			if err := json.Unmarshal(stdout.Bytes(), &report); err != nil {
				t.Fatalf("report: %v\n%s", err, &stdout)
			}
			if (report.Namespace != hostNS) != private {
				t.Fatalf("namespace = %q, host = %q, mode = %s", report.Namespace, hostNS, mode)
			}
			if !private {
				return
			}
			if len(report.Interfaces) != 1 || report.Interfaces[0] != "lo" {
				t.Fatalf("private interfaces = %v", report.Interfaces)
			}
			wantUp := mode == "isolated"
			if report.LoopbackUp != wantUp || report.TCPWorks != wantUp {
				t.Fatalf("loopback up=%t TCP works=%t, want %t", report.LoopbackUp, report.TCPWorks, wantUp)
			}
			if wantUp && !report.IPv4 {
				t.Fatal("isolated loopback missing 127.0.0.1/8")
			}
			if len(report.Caps) != 4 {
				t.Fatalf("missing capability fields: %v", report.Caps)
			}
			for _, cap := range report.Caps {
				if !strings.HasSuffix(cap, "0000000000000000") {
					t.Errorf("payload retains capability: %s", cap)
				}
			}
		})
	}
}

func TestPrintNetworkNamespace(t *testing.T) {
	for _, mode := range []networkMode{networkHost, networkNone, networkIsolated} {
		var out bytes.Buffer
		printNetworkNamespace(&out, mode)
		want := "host"
		if mode == networkNone {
			want = "loopback down"
		} else if mode == networkIsolated {
			want = "loopback up"
		}
		if !strings.Contains(out.String(), want) {
			t.Errorf("%s output = %q, want %q", mode, out.String(), want)
		}
	}
}

func TestNetworkSetupFailsClosed(t *testing.T) {
	self, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"none", "isolated"} {
		t.Run(mode, func(t *testing.T) {
			// This binary runs main in the parent, but exits during child setup.
			// If namespace creation itself is unavailable, that also must fail
			// closed. A fallback would execute the payload's --dry-run and print.
			cmd := exec.Command(self, "--net", mode, "--policy-json-from-env", "--", self, "--dry-run")
			cmd.Env = append(os.Environ(),
				helperEnv+"=network-fail-setup",
				publicPolicyEnvKey+`={"name":"network-setup-failure","net":"allow","fs":[{"path":"/","access":"rx"}]}`,
			)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if err == nil || stdout.Len() != 0 || !strings.Contains(stderr.String(), "refusing host network fallback") {
				t.Fatalf("expected fail-closed: err=%v stdout=%s stderr=%s", err, &stdout, &stderr)
			}
		})
	}
}
