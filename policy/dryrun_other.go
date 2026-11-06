//go:build !windows

package policy

import (
	"fmt"
	"io"
)

func platformDryRun(p *Policy, w io.Writer) error {
	return dryRunDefault(p, w)
}

// PrintSandboxFeatures reports native sandbox feature availability.
func PrintSandboxFeatures(w io.Writer) {
	feat, err := DetectFeatures()
	if err != nil {
		fmt.Fprintf(w, "Kernel features: unavailable (%v)\n", err)
		return
	}
	fmt.Fprintf(w, "Kernel features: %s\n", feat.String())
}
