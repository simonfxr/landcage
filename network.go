package main

import (
	"fmt"
	"io"
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
