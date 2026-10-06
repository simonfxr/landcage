//go:build !linux

package policy

import "fmt"

// DetectFeatures reports that Landlock is a Linux kernel feature.
func DetectFeatures() (LandlockFeatures, error) {
	return LandlockFeatures{}, fmt.Errorf("landlock not available")
}

// ValidateFSAccess has nothing to downgrade where Landlock is absent.
func (f LandlockFeatures) ValidateFSAccess(rule *FSRule) []string {
	return nil
}
