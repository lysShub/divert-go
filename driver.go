package divert

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/lysShub/go-dll"
	"golang.org/x/sys/windows"
)

func driverInstall[T string | dll.MemDLL](b T) error {
	switch b := any(b).(type) {
	case string:
		path, err := filepath.Abs(b)
		if err != nil {
			return err
		}
		loc, err := filepath.Abs("./")
		if err != nil {
			return err
		}

		if path == loc {
			// todo: use dll install
			return winDivertDriverInstall(path)
		}
		return winDivertDriverInstall(path)
	case dll.MemDLL:
		path := filepath.Join(os.TempDir(), fmt.Sprintf("WinDivert%d.sys", unsafe.Sizeof(int(0))*8))

		if _, err := os.Stat(path); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				// todo: validate existed driver is same as b
				if err := os.WriteFile(path, b, 0666); err != nil {
					return err
				}
			} else {
				return err
			}
		}
		return winDivertDriverInstall(path)
	default:
		panic("impossible")
	}
}

const WINDIVERT_DEVICE_NAME = "WinDivert"

func winDivertDriverInstall(sysPath string) error {
	const (
		WinDivertDriverInstallMutex = "WinDivertDriverInstallMutex"
	)

	pname, err := windows.UTF16PtrFromString(fmt.Sprintf("\\\\.\\%s", WINDIVERT_DEVICE_NAME))
	if err != nil {
		return err
	}

	h, err := windows.CreateFile(
		pname,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
		0,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OVERLAPPED,
		windows.InvalidHandle,
	)
	if err == nil {
		return windows.Close(h)
	} else if !errors.Is(err, windows.ERROR_FILE_NOT_FOUND) &&
		!errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {

		return err
	}

	// Install the WinDivert driver.
	// WinDivertDriverInstall
	{
		// Create & lock a named mutex.  This is to stop two processes trying
		// to start the driver at the same time.
		pmu, err := windows.UTF16PtrFromString(WinDivertDriverInstallMutex)
		if err != nil {
			return err
		}
		mutex, err := windows.CreateMutex(nil, false, pmu)
		if err != nil {
			return err
		}
		event, err := windows.WaitForSingleObject(mutex, windows.INFINITE)
		if err != nil {
			return err
		} else if event != windows.WAIT_OBJECT_0 && event != windows.WAIT_ABANDONED {
			return fmt.Errorf("WaitForSingleObject event %d", event)
		}

		var (
			manager, service   windows.Handle
			pdevice, ppathName *uint16
		)

		// Open the service manager:
		manager, err = windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
		if err != nil {
			goto WinDivertDriverInstallExit
		}

		// Check if the WinDivert service already exists; if so, start it.
		pdevice, err = windows.UTF16PtrFromString(WINDIVERT_DEVICE_NAME)
		if err != nil {
			goto WinDivertDriverInstallExit
		}
		service, err = windows.OpenService(manager, pdevice, windows.SERVICE_ALL_ACCESS)
		if err == nil {
			goto WinDivertDriverInstallExit
		}

		// Create the service:
		ppathName, err = windows.UTF16PtrFromString(sysPath)
		if err != nil {
			goto WinDivertDriverInstallExit
		}
		service, err = windows.CreateService(
			manager,
			pdevice,
			pdevice,
			windows.SERVICE_ALL_ACCESS,
			windows.SERVICE_KERNEL_DRIVER,
			windows.SERVICE_DEMAND_START,
			windows.SERVICE_ERROR_NORMAL,
			ppathName,
			nil, nil, nil, nil, nil,
		)
		if err != nil {
			if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
				service, _ = windows.OpenService(manager, pdevice, windows.SERVICE_ALL_ACCESS)
			}
			goto WinDivertDriverInstallExit
		}

		// Register event logging:
		_ = winDivertRegisterEventSource(sysPath)

	WinDivertDriverInstallExit:
		success := (service != 0)
		if service != 0 {
			//Start the service:
			err = windows.StartService(service, 0, nil)
			success = err == nil
			if !success {
				success = errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING)
			} else {
				// Mark the service for deletion.  This will cause the driver to
				// unload if (1) there are no more open handles, and (2) the
				// service is STOPPED or on system reboot.
				windows.DeleteService(service)
			}
		}

		if manager != 0 {
			windows.CloseServiceHandle(manager)
		}
		if service != 0 {
			windows.CloseServiceHandle(service)
		}
		windows.ReleaseMutex(mutex)
		windows.CloseHandle(mutex)

		if success {
			return nil
		} else {
			return err
		}
	}
}

// todo
func winDivertRegisterEventSource(sysPath string) error {
	// windows.RegisterEventSource()
	return nil
}
