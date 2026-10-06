//go:build darwin && !cgo

package policy

import "errors"

// Apply reports that Seatbelt cannot be installed without cgo. The Darwin
// cgo file is the one that links libsandbox.
func Apply(profile string, params []string) error {
	return errors.New("Darwin enforcement needs cgo")
}
