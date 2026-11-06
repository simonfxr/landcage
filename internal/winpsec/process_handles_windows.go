package winpsec

import (
	"errors"
	"fmt"
	"os"

	"golang.org/x/sys/windows"
)

func duplicateProcessStdio() (handles [3]windows.Handle, err error) {
	defer func() {
		if err != nil {
			err = errors.Join(err, closeProcessStdio(handles))
		}
	}()
	for i, file := range []*os.File{os.Stdin, os.Stdout, os.Stderr} {
		if err := windows.DuplicateHandle(windows.CurrentProcess(), windows.Handle(file.Fd()),
			windows.CurrentProcess(), &handles[i], 0, true, windows.DUPLICATE_SAME_ACCESS); err != nil {
			return handles, fmt.Errorf("duplicate stdio %d: %w", i, err)
		}
	}
	return handles, nil
}

func closeProcessStdio(handles [3]windows.Handle) (err error) {
	for _, handle := range handles {
		if handle != 0 {
			err = errors.Join(err, windows.CloseHandle(handle))
		}
	}
	return err
}

// Preserve a shared interactive console. As in the native reference runner,
// fully redirected stdio does not need a new console window.
func redirectedProcessStdio(handles [3]windows.Handle) bool {
	for _, handle := range handles {
		var mode uint32
		if windows.GetConsoleMode(handle, &mode) == nil {
			return false
		}
	}
	return true
}

func waitProcess(process windows.Handle) error {
	event, err := windows.WaitForSingleObject(process, windows.INFINITE)
	if err != nil {
		return fmt.Errorf("WaitForSingleObject(child): %w", err)
	}
	if event != windows.WAIT_OBJECT_0 {
		return fmt.Errorf("unexpected child wait result %#x", event)
	}
	return nil
}

// A process that failed before assignment is NOT covered by kill-on-job-close.
// Always terminate and reap it explicitly, even after a partial setup failure.
func terminateProcess(process windows.Handle) error {
	killErr := windows.TerminateProcess(process, 125)
	if killErr != nil {
		// TerminateProcess returns access denied for an already-exited process.
		event, waitErr := windows.WaitForSingleObject(process, 0)
		if waitErr == nil && event == windows.WAIT_OBJECT_0 {
			return nil
		}
		return errors.Join(fmt.Errorf("TerminateProcess: %w", killErr), waitErr)
	}
	return waitProcess(process)
}
