package winpsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"
	"unsafe"

	"golang.org/x/sys/windows"
)

// PathInfo describes an existing local disk path with no reparse traversal.
type PathInfo struct {
	Path  string
	IsDir bool
}

// ResolvePaths expands final-component globs only, while pinning their parent.
// Every path component, including the final one, must not be a reparse point.
// Returned paths are canonical; all inspection handles are closed before return.
func ResolvePaths(pattern string) (paths []PathInfo, err error) {
	if err := ValidatePath(pattern); err != nil {
		return nil, err
	}
	pattern = filepath.FromSlash(pattern)
	if !strings.ContainsAny(pattern, "*?[") {
		pin, err := pinLocalPath(pattern)
		if err != nil {
			return nil, err
		}
		return []PathInfo{pin.info}, pin.close()
	}
	dir, base := filepath.Split(pattern)
	if strings.ContainsAny(dir, "*?[") {
		return nil, fmt.Errorf("glob patterns only allowed in the final path component: %q", pattern)
	}
	if _, err := filepath.Match(base, ""); err != nil {
		return nil, fmt.Errorf("bad glob pattern %q: %w", base, err)
	}
	pin, err := pinLocalPath(filepath.Clean(dir))
	if err != nil {
		return nil, err
	}
	defer func() { err = errors.Join(err, pin.close()) }()
	if !pin.info.IsDir {
		return nil, fmt.Errorf("glob parent is not a directory: %s", dir)
	}
	// This native local-volume pathname cannot change underneath us: all its
	// prefixes are checked and held without WRITE or DELETE sharing.
	entries, err := os.ReadDir(pin.native)
	if err != nil {
		return nil, err
	}
	for _, entry := range entries {
		matched, err := filepath.Match(base, entry.Name())
		if err != nil {
			return nil, err
		}
		if !matched {
			continue
		}
		if err := ValidatePath(filepath.Join(dir, entry.Name())); err != nil {
			return nil, err
		}
		handle, info, err := openPathComponent(filepath.Join(pin.native, entry.Name()))
		if err != nil {
			return nil, err
		}
		if err := windows.CloseHandle(handle); err != nil {
			return nil, err
		}
		paths = append(paths, info)
	}
	return paths, nil
}

// PinPaths repeats no-reparse validation for every filesystem grant. The caller
// must keep these anchors through Create, then release BEFORE launching children:
// retaining ancestor handles can interfere with payload ACL/filesystem operations.
// No ACL handles are opened. On failure all acquired handles are released.
// The returned release function is idempotent, but not concurrency-safe.
func PinPaths(spec Spec) (release func() error, err error) {
	var pins []*pathPin
	release = func() error {
		var errs []error
		for i := len(pins) - 1; i >= 0; i-- {
			errs = append(errs, pins[i].close())
		}
		pins = nil
		return errors.Join(errs...)
	}
	for _, paths := range [][]string{spec.ReadOnlyPaths, spec.ReadWritePaths, spec.DeniedPaths} {
		for _, path := range paths {
			pin, err := pinLocalPath(path)
			if err != nil {
				return nil, errors.Join(err, release())
			}
			pins = append(pins, pin)
		}
	}
	return release, nil
}

type pathPin struct {
	handles []windows.Handle
	native  string
	info    PathInfo
}

func (p *pathPin) close() error {
	var errs []error
	for i := len(p.handles) - 1; i >= 0; i-- {
		errs = append(errs, windows.CloseHandle(p.handles[i]))
	}
	p.handles = nil
	return errors.Join(errs...)
}

func pinLocalPath(path string) (_ *pathPin, err error) {
	if err := ValidatePath(path); err != nil {
		return nil, err
	}
	if strings.ContainsAny(path, "*?") {
		return nil, fmt.Errorf("wildcards are not allowed in literal grant paths: %q", path)
	}
	path = filepath.Clean(filepath.FromSlash(path))
	root, err := localVolumeRoot(filepath.VolumeName(path))
	if err != nil {
		return nil, err
	}
	pin := &pathPin{native: root}
	defer func() {
		if err != nil {
			err = errors.Join(err, pin.close())
		}
	}()
	parts := []string{""} // Inspect and pin the root before opening any children.
	if len(path) > 3 {
		parts = append(parts, strings.Split(path[3:], `\`)...)
	}
	for i, part := range parts {
		if part != "" {
			pin.native = filepath.Join(pin.native, part)
		}
		handle, info, err := openPathComponent(pin.native)
		if err != nil {
			return nil, err
		}
		pin.handles = append(pin.handles, handle)
		pin.info = info
		if i < len(parts)-1 && !info.IsDir {
			return nil, fmt.Errorf("path ancestor is not a directory: %s", info.Path)
		}
	}
	return pin, nil
}

// Query the DOS mapping without opening it. Open the known local kernel volume
// directly, never a potentially remote/mutable drive alias or SUBST target.
func localVolumeRoot(volume string) (string, error) {
	name, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		return "", err
	}
	var target [32768]uint16
	if _, err := windows.QueryDosDevice(name, &target[0], uint32(len(target))); err != nil {
		return "", fmt.Errorf("query local drive %s: %w", volume, err)
	}
	device := windows.UTF16ToString(target[:])
	number, ok := strings.CutPrefix(device, `\Device\HarddiskVolume`)
	if !ok || number == "" || strings.Trim(number, "0123456789") != "" {
		return "", fmt.Errorf("only local Windows disk volumes are supported: %s maps to %s", volume, device)
	}
	return `\\?\GLOBALROOT` + device + `\`, nil
}

func openPathComponent(path string) (handle windows.Handle, info PathInfo, err error) {
	name, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return 0, info, err
	}
	// Attribute-only handles do not participate in Windows sharing checks.
	// READ_DATA (LIST_DIRECTORY for directories) is required for this handle
	// to actually exclude concurrent writers/reparse mutation and deletion.
	handle, err = windows.CreateFile(name, windows.FILE_READ_ATTRIBUTES|windows.FILE_READ_DATA, windows.FILE_SHARE_READ,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_OPEN_REPARSE_POINT|windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return 0, info, &os.PathError{Op: "pin local path", Path: path, Err: err}
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, windows.CloseHandle(handle))
		}
	}()
	var attrs windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &attrs); err != nil {
		return handle, info, err
	}
	if attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return handle, info, fmt.Errorf("reparse traversal is unsupported (including symlinks, junctions and mount points): %s", path)
	}
	kind, err := windows.GetFileType(handle)
	if err != nil {
		return handle, info, err
	}
	if kind != windows.FILE_TYPE_DISK || attrs.FileAttributes&windows.FILE_ATTRIBUTE_DEVICE != 0 {
		return handle, info, fmt.Errorf("only local disk files and directories are supported: %s", path)
	}
	info.IsDir = attrs.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if info.IsDir {
		var caseFlags uint32
		if err := windows.GetFileInformationByHandleEx(handle, windows.FileCaseSensitiveInfo,
			(*byte)(unsafe.Pointer(&caseFlags)), uint32(unsafe.Sizeof(caseFlags))); err != nil {
			return handle, info, fmt.Errorf("query directory case-sensitivity: %w", err)
		}
		if caseFlags != 0 {
			return handle, info, fmt.Errorf("case-sensitive directories are unsupported: %s", path)
		}
	}
	var canonical [32768]uint16
	n, err := windows.GetFinalPathNameByHandle(handle, &canonical[0], uint32(len(canonical)), 0)
	if err != nil {
		return handle, info, err
	}
	if n >= uint32(len(canonical)) {
		return handle, info, fmt.Errorf("canonical path exceeds Windows path limit")
	}
	info.Path = strings.TrimPrefix(windows.UTF16ToString(canonical[:n]), `\\?\`)
	if err := ValidatePath(info.Path); err != nil {
		return handle, info, err
	}
	return handle, info, nil
}

// ValidatePath rejects namespace/normalization aliases before any path access.
// Wildcards are permitted here; ResolvePaths restricts them to the last component.
func ValidatePath(path string) error {
	volume := filepath.VolumeName(path)
	if !utf8.ValidString(path) || len(volume) != 2 || volume[1] != ':' ||
		!((volume[0] >= 'A' && volume[0] <= 'Z') || (volume[0] >= 'a' && volume[0] <= 'z')) ||
		!filepath.IsAbs(path) {
		return fmt.Errorf("path must be an unambiguous local drive-absolute Windows path: %q", path)
	}
	for _, ch := range path[2:] {
		if ch < 32 || strings.ContainsRune(`:<>|"`, ch) {
			return fmt.Errorf("device paths, alternate data streams and invalid Windows names are unsupported: %q", path)
		}
	}
	for _, part := range strings.FieldsFunc(path[3:], func(ch rune) bool { return ch == '\\' || ch == '/' }) {
		if !filepath.IsLocal(part) || reservedPathName(part) || strings.HasSuffix(part, ".") || strings.HasSuffix(part, " ") {
			return fmt.Errorf("reserved or ambiguous Windows path component %q", part)
		}
	}
	return nil
}

func reservedPathName(part string) bool {
	base, _, _ := strings.Cut(part, ".")
	base = strings.ToUpper(strings.TrimRight(base, " "))
	switch base {
	case "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$":
		return true
	}
	if strings.HasPrefix(base, "COM") || strings.HasPrefix(base, "LPT") {
		switch base[3:] {
		case "1", "2", "3", "4", "5", "6", "7", "8", "9", "¹", "²", "³":
			return true
		}
	}
	return false
}
