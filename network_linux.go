//go:build linux

package main

import (
	"fmt"

	"golang.org/x/sys/unix"
)

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
