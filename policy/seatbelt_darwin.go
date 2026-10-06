//go:build darwin && cgo

package policy

/*
#cgo LDFLAGS: -lsandbox
#include <stdlib.h>
#include <stdint.h>

extern int sandbox_init_with_parameters(const char *profile, uint64_t flags,
    const char *const parameters[], char **errorbuf);
*/
import "C"
import (
	"fmt"
	"unsafe"
)

// Apply installs profile on this process. flags is 0 for an SBPL string.
// params is a sequence of key, value, key, value, …. libsandbox is not safe
// for concurrent callers; call Apply once, immediately before exec.
func Apply(profile string, params []string) error {
	cProfile := C.CString(profile)
	defer C.free(unsafe.Pointer(cProfile))

	// NULL-terminated key/value pairs. A single trailing NULL is an empty list.
	cParams := make([]*C.char, len(params)+1)
	for i, s := range params {
		cParams[i] = C.CString(s)
		defer C.free(unsafe.Pointer(cParams[i]))
	}
	var errbuf *C.char
	rc := C.sandbox_init_with_parameters(
		cProfile, 0, (**C.char)(unsafe.Pointer(&cParams[0])), &errbuf)
	if rc != 0 {
		msg := "sandbox_init_with_parameters failed"
		if errbuf != nil {
			msg = C.GoString(errbuf)
			C.free(unsafe.Pointer(errbuf))
		}
		return fmt.Errorf("seatbelt: %s", msg)
	}
	return nil
}
