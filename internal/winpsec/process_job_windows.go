package winpsec

import (
	"errors"
	"fmt"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var isProcessInJob = windows.NewLazySystemDLL("kernel32.dll").NewProc("IsProcessInJob")

type processState struct {
	environment *Environment
	job         windows.Handle
	process     windows.ProcessInformation
	assigned    bool
}

type processJobAccounting struct {
	totalUserTime, totalKernelTime, periodUserTime, periodKernelTime int64
	pageFaults, totalProcesses, activeProcesses, terminatedProcesses uint32
}

func newProcessJob() (windows.Handle, error) {
	job, err := windows.CreateJobObject(nil, nil) // non-inheritable, unnamed
	if err != nil {
		return 0, fmt.Errorf("CreateJobObject: %w", err)
	}
	var limits windows.JOBOBJECT_EXTENDED_LIMIT_INFORMATION
	// Do not set BREAKAWAY_OK or SILENT_BREAKAWAY_OK. Neither job nor PSEC
	// handle is ever included in the inherited HANDLE_LIST.
	limits.BasicLimitInformation.LimitFlags = windows.JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
	_, err = windows.SetInformationJobObject(job, windows.JobObjectExtendedLimitInformation,
		uintptr(unsafe.Pointer(&limits)), uint32(unsafe.Sizeof(limits)))
	if err != nil {
		return 0, errors.Join(fmt.Errorf("SetInformationJobObject: %w", err), windows.CloseHandle(job))
	}
	return job, nil
}

func verifyProcessJob(process, job windows.Handle) error {
	var member int32
	// IsProcessInJob returns BOOL, not HRESULT. LastError matters only when
	// the function returns zero; member is the separate membership result.
	result, _, callErr := isProcessInJob.Call(uintptr(process), uintptr(job), uintptr(unsafe.Pointer(&member)))
	if result == 0 {
		if callErr == windows.ERROR_SUCCESS {
			callErr = windows.ERROR_GEN_FAILURE
		}
		return fmt.Errorf("IsProcessInJob: %w", callErr)
	}
	if member == 0 {
		return errors.New("suspended child is not in the mandatory kill-on-close job")
	}
	return nil
}

func drainProcessJob(job windows.Handle) error {
	if err := windows.TerminateJobObject(job, 125); err != nil {
		return fmt.Errorf("TerminateJobObject: %w", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for {
		var accounting processJobAccounting
		err := windows.QueryInformationJobObject(job, windows.JobObjectBasicAccountingInformation,
			uintptr(unsafe.Pointer(&accounting)), uint32(unsafe.Sizeof(accounting)), nil)
		if err != nil {
			return fmt.Errorf("QueryInformationJobObject: %w", err)
		}
		if accounting.activeProcesses == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return errors.New("native PSEC job did not drain within 30 seconds")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func (s *processState) close() (err error) {
	safe := true
	if s.job != 0 {
		// Keep the environment alive until ALL descendants have exited, not
		// merely the root process. Closing the job is a final kill-on-close
		// backstop even if explicit termination or accounting failed.
		drainErr := drainProcessJob(s.job)
		safe = drainErr == nil
		err = errors.Join(err, drainErr, windows.CloseHandle(s.job))
	}
	if s.process.Process != 0 {
		var reapErr error
		if s.assigned && safe {
			reapErr = waitProcess(s.process.Process)
		} else {
			reapErr = terminateProcess(s.process.Process)
		}
		safe = safe && reapErr == nil
		err = errors.Join(err, reapErr)
	}
	if s.process.Thread != 0 {
		err = errors.Join(err, windows.CloseHandle(s.process.Thread))
	}
	if s.process.Process != 0 {
		err = errors.Join(err, windows.CloseHandle(s.process.Process))
	}
	if !safe {
		// Fail closed: never tear down the environment while a process may
		// still be using it. Its opaque native handle is deliberately retained
		// until parent exit; Close has no rollback or error reporting.
		return errors.Join(err, errors.New("cannot verify native PSEC tree cleanup; environment retained until parent exit"))
	}
	return errors.Join(err, s.environment.Close())
}
