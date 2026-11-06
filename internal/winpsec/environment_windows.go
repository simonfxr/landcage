package winpsec

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ABI and constants follow Microsoft's mxc secenv.rs; see schema/README.md.
// HRESULTs, not GetLastError, determine success for create/query/version.
type environmentAPI struct {
	create  *windows.LazyProc
	query   *windows.LazyProc
	version *windows.LazyProc // optional on baseline PSEC 1.0 hosts
	close   *windows.LazyProc
}

var loadAPI = sync.OnceValues(func() (*environmentAPI, error) {
	// Do not allow WOW64 filesystem redirection to make the launched image
	// differ from the local file inspected and pinned by a 32-bit launcher.
	if runtime.GOARCH != "amd64" && runtime.GOARCH != "arm64" {
		return nil, fmt.Errorf("%w: the Windows backend requires a 64-bit executable", ErrUnsupported)
	}
	dll := windows.NewLazySystemDLL("processmodel.dll")
	api := &environmentAPI{
		create: dll.NewProc("CreateProcessSecurityEnvironment"),
		query:  dll.NewProc("QueryProcessSecurityEnvironmentSupport"),
		close:  dll.NewProc("CloseProcessSecurityEnvironment"),
	}
	for _, proc := range []*windows.LazyProc{api.create, api.query, api.close} {
		if err := proc.Find(); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrUnsupported, proc.Name, err)
		}
	}
	version := dll.NewProc("IsProcessSecurityEnvironmentVersionSupported")
	if version.Find() == nil {
		api.version = version
	}
	return api, nil
})

// CheckSupport loads the native API and queries baseline PSEC 1.0 support.
// It does not create an environment or certify runtime policy enforcement.
func CheckSupport() error {
	api, err := loadAPI()
	if err != nil {
		return err
	}
	return api.checkSupport(0)
}

// Environment owns an HPROCESS_SECURITY_ENVIRONMENT, not a kernel handle.
// Close must be called after all contained children exit. Do not use CloseHandle.
// Do not copy an Environment or close it concurrently with a process launch.
type Environment struct {
	mu     sync.Mutex
	handle uintptr
	api    *environmentAPI
}

// Create creates an environment from an Encode result using flags=0
// (PROCESS_SECURITY_ENVIRONMENT_FLAG_NONE). No alternate backend is attempted.
// Success does not launch a process or demonstrate policy enforcement.
func Create(blob []byte) (*Environment, error) {
	if uint64(len(blob)) > uint64(^uint32(0)) {
		return nil, fmt.Errorf("PSEC buffer exceeds DWORD size")
	}
	required, err := requiredSupport(blob)
	if err != nil {
		return nil, err
	}
	api, err := loadAPI()
	if err != nil {
		return nil, err
	}
	if err := api.checkSupport(required); err != nil {
		return nil, err
	}
	var handle uintptr
	// HRESULT CreateProcessSecurityEnvironment(LPCVOID, DWORD, flags, HANDLE*).
	result, _, _ := api.create.Call(
		uintptr(unsafe.Pointer(&blob[0])), uintptr(uint32(len(blob))), 0,
		uintptr(unsafe.Pointer(&handle)),
	)
	runtime.KeepAlive(blob)
	if err := hresult("CreateProcessSecurityEnvironment", result); err != nil {
		return nil, err
	}
	if handle == 0 {
		return nil, fmt.Errorf("CreateProcessSecurityEnvironment returned a null handle")
	}
	return &Environment{handle: handle, api: api}, nil
}

func (api *environmentAPI) checkSupport(required uint64) error {
	if api.version != nil {
		// BOOLEAN is one byte; DWORD is four bytes.
		var available uint8
		var minor uint32
		result, _, _ := api.version.Call(1,
			uintptr(unsafe.Pointer(&available)), uintptr(unsafe.Pointer(&minor)))
		if err := hresult("IsProcessSecurityEnvironmentVersionSupported", result); err != nil {
			return err
		}
		if available == 0 {
			return fmt.Errorf("%w: PSEC version 1.0 unavailable", ErrUnsupported)
		}
	}
	// Missing optional version export means baseline 1.0, exactly as in secenv.rs.
	var support uint64
	result, _, _ := api.query.Call(uintptr(unsafe.Pointer(&support)))
	if err := hresult("QueryProcessSecurityEnvironmentSupport", result); err != nil {
		return err
	}
	return checkSupport(support, required)
}

func hresult(function string, result uintptr) error {
	if int32(uint32(result)) < 0 {
		return fmt.Errorf("%s failed: HRESULT 0x%08x", function, uint32(result))
	}
	return nil
}

// Handle returns the borrowed environment handle, or zero after Close.
// The owner must remain open through creation and the lifetime of its children.
func (e *Environment) Handle() uintptr {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.handle
}

// Close calls the void CloseProcessSecurityEnvironment export exactly once.
// The native API cannot report close failures. A nil or already closed owner is harmless.
func (e *Environment) Close() error {
	if e == nil {
		return nil
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.handle != 0 {
		e.api.close.Call(e.handle)
		e.handle = 0
	}
	return nil
}
