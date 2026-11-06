package main

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/simonfxr/landcage/internal/winpsec"
)

// resolveExecutable implements Windows LookPath without os.Stat/LookPath on
// unchecked paths. Every probe uses local-volume, no-reparse ResolvePaths; an
// unsafe PATH entry is an error, not something to silently search past.
// GODEBUG=execerrdot=0 deliberately cannot enable implicit CWD execution.
func resolveExecutable(name string) (string, error) {
	path, err := resolveLocalExecutable(name)
	if err != nil {
		return path, &exec.Error{Name: name, Err: err}
	}
	return path, nil
}

func resolveLocalExecutable(name string) (string, error) {
	if name == "" {
		return "", exec.ErrNotFound
	}
	if strings.ContainsAny(name, "*?[") || strings.HasSuffix(name, `\`) || strings.HasSuffix(name, "/") ||
		filepath.Base(name) == "." || filepath.Base(name) == ".." {
		return "", fmt.Errorf("executable must be a literal file path, not a glob or directory")
	}
	exts, err := executableExtensions()
	if err != nil {
		return "", err
	}
	if strings.ContainsAny(name, `:\/`) {
		return findLocalExecutable(name, exts)
	}
	var dotPath string
	if _, skip := os.LookupEnv("NoDefaultCurrentDirectoryInExePath"); !skip {
		dotPath, err = findLocalExecutable(filepath.Join(".", name), exts)
		if err != nil && !missingExecutable(err) {
			return "", err
		}
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue // Windows/Go do not interpret empty PATH entries as ".".
		}
		path, err := findLocalExecutable(filepath.Join(dir, name), exts)
		if err != nil {
			if missingExecutable(err) {
				continue
			}
			return "", fmt.Errorf("unsafe or inaccessible PATH entry %q; use an explicit local executable path: %w", dir, err)
		}
		if dotPath != "" {
			same, err := sameLocalExecutable(dotPath, path)
			if err != nil {
				return "", err
			}
			if !same {
				return dotPath, exec.ErrDot
			}
		}
		if !filepath.IsAbs(dir) {
			if dotPath == "" {
				dotPath = path
			}
			continue
		}
		return path, nil
	}
	if dotPath != "" {
		return dotPath, exec.ErrDot
	}
	return "", exec.ErrNotFound
}

func executableExtensions() ([]string, error) {
	value := os.Getenv("PATHEXT")
	if value == "" {
		return []string{".com", ".exe", ".bat", ".cmd"}, nil
	}
	var exts []string
	for _, ext := range strings.Split(strings.ToLower(value), ";") {
		if ext == "" {
			continue
		}
		if !strings.HasPrefix(ext, ".") {
			ext = "." + ext
		}
		if strings.ContainsAny(ext, `\/:*?[]<>|"`) {
			return nil, fmt.Errorf("unsafe PATHEXT suffix %q", ext)
		}
		if err := winpsec.ValidatePath(`C:\executable` + ext); err != nil {
			return nil, fmt.Errorf("invalid PATHEXT suffix: %w", err)
		}
		exts = append(exts, ext)
	}
	return exts, nil
}

func findLocalExecutable(name string, exts []string) (string, error) {
	// Validate the raw namespace before Abs/Join can normalize it. No filesystem
	// lookup (including remote or drive-relative lookup) happens at this stage.
	volume := filepath.VolumeName(name)
	if volume != "" && (len(volume) != 2 || volume[1] != ':' || !filepath.IsAbs(name)) {
		return "", fmt.Errorf("executable lookup requires local drive-absolute paths, not UNC/device/drive-relative paths: %q", name)
	}
	if strings.ContainsAny(name, "*?[") {
		return "", fmt.Errorf("glob executable lookup is unsupported: %q", name)
	}
	absolute, err := filepath.Abs(name)
	if err != nil {
		return "", err
	}
	if err := winpsec.ValidatePath(absolute); err != nil {
		return "", err
	}
	hasExt := filepath.Ext(absolute) != ""
	var candidates []string
	if len(exts) == 0 || hasExt {
		candidates = append(candidates, absolute)
	}
	for _, ext := range exts {
		candidates = append(candidates, absolute+ext)
	}
	for _, candidate := range candidates {
		paths, err := winpsec.ResolvePaths(candidate)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				continue
			}
			return "", err
		}
		if len(paths) == 1 && !paths[0].IsDir {
			return paths[0].Path, nil
		}
	}
	if hasExt {
		return "", os.ErrNotExist
	}
	return "", exec.ErrNotFound
}

func missingExecutable(err error) bool {
	return errors.Is(err, os.ErrNotExist) || errors.Is(err, exec.ErrNotFound)
}

func sameLocalExecutable(a, b string) (_ bool, err error) {
	if strings.EqualFold(a, b) {
		return true, nil
	}
	// Preserve Go's same-file exception for an explicit absolute PATH entry
	// (including hardlinks), but never call Stat on unpinned pathnames.
	release, err := winpsec.PinPaths(winpsec.Spec{ReadOnlyPaths: []string{a, b}})
	if err != nil {
		return false, err
	}
	defer func() { err = errors.Join(err, release()) }()
	first, err := os.Stat(a)
	if err != nil {
		return false, err
	}
	second, err := os.Stat(b)
	if err != nil {
		return false, err
	}
	return os.SameFile(first, second), nil
}
