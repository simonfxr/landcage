package main

import (
	"fmt"
	"io"

	"golang.org/x/sys/unix"
)

// networkMode selects namespace isolation, independently of Landlock port rules.
type networkMode string

const (
	networkHost     networkMode = "host"
	networkNone     networkMode = "none"
	networkIsolated networkMode = "isolated"
)

func (m *networkMode) UnmarshalText(text []byte) error {
	switch mode := networkMode(text); mode {
	case networkHost, networkNone, networkIsolated:
		*m = mode
		return nil
	default:
		return fmt.Errorf("--net must be host, none, or isolated (got %q)", text)
	}
}

func (m networkMode) private() bool {
	return m == networkNone || m == networkIsolated
}

func printNetworkNamespace(w io.Writer, mode networkMode) {
	switch mode {
	case networkNone:
		fmt.Fprintln(w, "Network namespace: private (loopback down)")
	case networkIsolated:
		fmt.Fprintln(w, "Network namespace: private (loopback up, no external interfaces)")
	default:
		fmt.Fprintln(w, "Network namespace: host")
	}
}

// A fresh network namespace has only lo, initially down. Bringing it up also
// configures the kernel's loopback addresses (127.0.0.1 and, if enabled, ::1).
// Do this before dropping CAP_NET_ADMIN and enforcing Landlock.
func bringLoopbackUp() error {
	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM|unix.SOCK_CLOEXEC, 0)
	if err != nil {
		return fmt.Errorf("opening loopback control socket: %w", err)
	}
	defer unix.Close(fd)

	ifr, err := unix.NewIfreq("lo")
	if err != nil {
		return fmt.Errorf("creating loopback request: %w", err)
	}
	if err := unix.IoctlIfreq(fd, unix.SIOCGIFFLAGS, ifr); err != nil {
		return fmt.Errorf("reading loopback flags: %w", err)
	}
	ifr.SetUint16(ifr.Uint16() | unix.IFF_UP)
	if err := unix.IoctlIfreq(fd, unix.SIOCSIFFLAGS, ifr); err != nil {
		return fmt.Errorf("bringing loopback up: %w", err)
	}
	return nil
}
