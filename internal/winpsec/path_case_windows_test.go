package winpsec

import (
	"path/filepath"
	"strings"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestProcessPathContainsPreservesCanonicalCase(t *testing.T) {
	if processPathContains(`C:\root\Allowed`, `C:\root\allowed\payload.exe`) {
		t.Fatal("distinct canonical directory spellings were folded into a grant")
	}
	if !processPathContains(`C:\root\Allowed`, `C:\root\Allowed\payload.exe`) {
		t.Fatal("canonical descendant not recognized")
	}
}

func TestResolvePathsRejectsCaseSensitiveDirectories(t *testing.T) {
	dir := t.TempDir()
	name, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		t.Fatal(err)
	}
	h, err := windows.CreateFile(name, windows.FILE_WRITE_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		t.Fatal(err)
	}
	var flags uint32 = 1 // FILE_CS_FLAG_CASE_SENSITIVE_DIR
	err = windows.SetFileInformationByHandle(h, windows.FileCaseSensitiveInfo,
		(*byte)(unsafe.Pointer(&flags)), uint32(unsafe.Sizeof(flags)))
	windows.CloseHandle(h)
	if err != nil {
		t.Skipf("host/user cannot enable directory case sensitivity: %v", err)
	}
	file := testPathFile(t, dir, "payload.exe")
	for _, path := range []string{dir, file, filepath.Join(dir, "*")} {
		if _, err := ResolvePaths(path); err == nil || !strings.Contains(err.Error(), "case-sensitive") {
			t.Fatalf("case-sensitive traversal %q: %v", path, err)
		}
	}
}
