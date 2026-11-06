package winpsec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	procThreadAttributeSecurityEnvironment = 0x00020023
	statusDLLInitFailed                    = 0xc0000142
)

// Run launches bin in a native process security environment and waits for it.
// bin must be resolved and absolute; args is the full argv, including argv[0].
// env is explicit: nil and empty both mean an empty environment, never inheritance.
// The current directory and stdio are preserved. A nonzero child exit status is
// returned unchanged, not converted to an error (except for DLL-init diagnostics).
//
// This is not a legacy AppContainer fallback: Create and the security-environment
// attribute are mandatory. All descendants are killed and reaped before the
// environment is closed, including on setup/resume failures. Job assignment is
// verified before any payload code runs. Current PSEC ignores JOB_LIST at
// creation, so abrupt launcher death before assignment can leave a suspended
// process; after assignment the non-inherited job provides kill-on-close.
func Run(spec Spec, bin string, args []string, env []string) (code uint32, err error) {
	if !filepath.IsAbs(bin) || !validProcessString(bin) {
		return 0, errors.New("Windows executable must be an absolute UTF-8 path without NUL")
	}
	bin, releasePaths, err := pinProcessPaths(spec, bin)
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, releasePaths()) }()
	app, err := windows.UTF16PtrFromString(bin)
	if err != nil {
		return 0, err
	}
	command, err := commandLine(args)
	if err != nil {
		return 0, err
	}
	block, err := environmentBlock(env)
	if err != nil {
		return 0, err
	}
	currentDir, err := os.Getwd()
	if err != nil {
		return 0, fmt.Errorf("current directory: %w", err)
	}
	cwd, err := windows.UTF16PtrFromString(currentDir)
	if err != nil {
		return 0, err
	}
	user, err := verifyCaller()
	if err != nil {
		return 0, err
	}
	blob, err := Encode(spec)
	if err != nil {
		return 0, err
	}
	environment, err := Create(blob)
	if err != nil {
		return 0, err
	}
	state := processState{environment: environment}
	defer func() { err = errors.Join(err, state.close()) }()
	state.job, err = newProcessJob()
	if err != nil {
		return 0, err
	}
	stdio, err := duplicateProcessStdio()
	if err != nil {
		return 0, err
	}
	defer func() { err = errors.Join(err, closeProcessStdio(stdio)) }()
	attributes, err := windows.NewProcThreadAttributeList(2)
	if err != nil {
		return 0, fmt.Errorf("InitializeProcThreadAttributeList: %w", err)
	}
	defer attributes.Delete()
	// Update takes a pointer TO the opaque PSEC handle, not the handle itself.
	environmentHandle := environment.Handle()
	if err := attributes.Update(procThreadAttributeSecurityEnvironment,
		unsafe.Pointer(&environmentHandle), unsafe.Sizeof(environmentHandle)); err != nil {
		return 0, fmt.Errorf("UpdateProcThreadAttribute(SECURITY_ENVIRONMENT): %w", err)
	}
	if err := attributes.Update(windows.PROC_THREAD_ATTRIBUTE_HANDLE_LIST,
		unsafe.Pointer(&stdio[0]), unsafe.Sizeof(stdio)); err != nil {
		return 0, fmt.Errorf("UpdateProcThreadAttribute(HANDLE_LIST): %w", err)
	}
	startup := windows.StartupInfoEx{}
	startup.Cb = uint32(unsafe.Sizeof(startup)) // full STARTUPINFOEX, not STARTUPINFO
	startup.Flags = windows.STARTF_USESTDHANDLES
	startup.StdInput, startup.StdOutput, startup.StdErr = stdio[0], stdio[1], stdio[2]
	startup.ProcThreadAttributeList = attributes.List()
	flags := uint32(windows.CREATE_SUSPENDED | windows.EXTENDED_STARTUPINFO_PRESENT | windows.CREATE_UNICODE_ENVIRONMENT)
	if redirectedProcessStdio(stdio) {
		flags |= windows.CREATE_NO_WINDOW
	}
	err = windows.CreateProcess(app, &command[0], nil, nil, true, flags,
		&block[0], cwd, &startup.StartupInfo, &state.process)
	runtime.KeepAlive(environmentHandle)
	runtime.KeepAlive(stdio)
	runtime.KeepAlive(attributes)
	if err != nil {
		return 0, fmt.Errorf("CreateProcessW(SECURITY_ENVIRONMENT): %w", err)
	}
	// Match the native reference backend. On measured build 26300.9711,
	// CreateProcess accepts JOB_LIST alongside PSEC but does not assign that
	// job. Never infer membership from successful attribute registration.
	if err := windows.AssignProcessToJobObject(state.job, state.process.Process); err != nil {
		return 0, fmt.Errorf("AssignProcessToJobObject (child never resumed): %w", err)
	}
	if err := verifyProcessJob(state.process.Process, state.job); err != nil {
		return 0, fmt.Errorf("verify job assignment (child never resumed): %w", err)
	}
	state.assigned = true
	if err := verifyChildToken(state.process.Process, user); err != nil {
		return 0, fmt.Errorf("verify suspended native PSEC child: %w", err)
	}
	// PSEC may resolve paths during CreateProcess, so retain all anchors through
	// suspended image creation. Release before any payload code runs: pinning
	// ancestors without write/delete sharing would interfere with Git renames.
	if err := releasePaths(); err != nil {
		return 0, fmt.Errorf("release native PSEC path anchors (child never resumed): %w", err)
	}
	count, err := windows.ResumeThread(state.process.Thread)
	if err != nil {
		return 0, fmt.Errorf("ResumeThread: %w", err)
	}
	if count != 1 {
		return 0, fmt.Errorf("unexpected initial suspend count %d", count)
	}
	if err := waitProcess(state.process.Process); err != nil {
		return 0, err
	}
	if err := windows.GetExitCodeProcess(state.process.Process, &code); err != nil {
		return 0, fmt.Errorf("GetExitCodeProcess: %w", err)
	}
	if code == statusDLLInitFailed {
		return code, errors.New("native PSEC child exited with STATUS_DLL_INIT_FAILED (0xc0000142): this runtime may require an interactive Windows session (PowerShell/Git DLL initialization can fail in session 0); sandbox protections were not weakened")
	}
	return code, nil
}
