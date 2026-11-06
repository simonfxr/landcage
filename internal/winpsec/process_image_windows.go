package winpsec

import (
	"fmt"
	"path/filepath"
	"strings"
)

// pinProcessPaths repeats Compile's validation and pins both policy anchors and
// the initial image. The extra image path is for pinning ONLY, never an implicit
// grant: the actual spec sent to Create must remain unchanged.
func pinProcessPaths(spec Spec, bin string) (string, func() error, error) {
	if strings.ContainsAny(bin, "*?[") {
		return "", nil, fmt.Errorf("initial executable must be a literal local file, not a glob")
	}
	images, err := ResolvePaths(bin)
	if err != nil {
		return "", nil, fmt.Errorf("initial executable: %w", err)
	}
	if len(images) != 1 || images[0].IsDir {
		return "", nil, fmt.Errorf("initial executable must be a local regular file")
	}
	image := images[0].Path
	for _, denied := range spec.DeniedPaths {
		if processPathContains(denied, image) {
			return "", nil, fmt.Errorf("initial executable is inside a denied filesystem path: %s", image)
		}
	}
	granted := false
	for _, paths := range [][]string{spec.ReadOnlyPaths, spec.ReadWritePaths} {
		for _, grant := range paths {
			if processPathContains(grant, image) {
				granted = true
			}
		}
	}
	if !granted {
		return "", nil, fmt.Errorf("initial executable must be inside an explicit rx or read-write filesystem grant: %s", image)
	}
	pins := spec
	pins.ReadOnlyPaths = append(append([]string(nil), spec.ReadOnlyPaths...), image)
	release, err := PinPaths(pins)
	if err != nil {
		return "", nil, fmt.Errorf("pin native PSEC paths: %w", err)
	}
	return image, release, nil
}

func processPathContains(parent, child string) bool {
	parent = filepath.Clean(filepath.FromSlash(parent))
	child = filepath.Clean(filepath.FromSlash(child))
	// Both paths are canonical, obtained from filesystem handles. Do not fold
	// distinct stored spellings into one authorization decision. Preparation
	// also rejects case-sensitive directories, rather than assuming NTFS is
	// universally case-insensitive.
	return parent == child || strings.HasPrefix(child, strings.TrimRight(parent, `\`)+`\`)
}
