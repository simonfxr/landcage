//go:build !linux

package main

import "fmt"

func bringLoopbackUp() error {
	return fmt.Errorf("network namespaces are not supported on this platform")
}
