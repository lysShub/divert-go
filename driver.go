//go:build windows
// +build windows

package divert

import (
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"github.com/pkg/errors"

	"golang.org/x/sys/windows"
)

func driverInstall(b []byte) error {
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
	return _WinDivertDriverInstall(path)
}

const WINDIVERT_DEVICE_NAME = "WinDivert"
const WinDivertDriverInstallMutex = "WinDivertDriverInstallMutex"

// Install the WinDivert driver.
func _WinDivertDriverInstall(sysPath string) error {
	if installed, err := winDivertDriverInstalled(); err != nil {
		return err
	} else if installed {
		return nil
	}
	mu, err := winDivertDriverMutex()
	if err != nil {
		return err
	}
	if err := mu.Lock(); err != nil {
		return err
	}
	defer mu.Unlock()

	// Open the service manager:
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)

	// Check if the WinDivert service already exists; if so, start it.
	pdevice, err := windows.UTF16PtrFromString(WINDIVERT_DEVICE_NAME)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, pdevice, windows.SERVICE_ALL_ACCESS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			// Create the service:
			psysPath, err := windows.UTF16PtrFromString(sysPath)
			if err != nil {
				return err
			}

			service, err = windows.CreateService(
				manager,                       // hSCManager
				pdevice,                       // lpServiceName
				pdevice,                       // lpDisplayName
				windows.SERVICE_ALL_ACCESS,    // dwDesiredAccess
				windows.SERVICE_KERNEL_DRIVER, // dwServiceType
				windows.SERVICE_DEMAND_START,  // dwStartType
				windows.SERVICE_ERROR_NORMAL,  // dwErrorControl
				psysPath,                      // lpBinaryPathName
				nil, nil, nil, nil, nil,
			)
			if err != nil {
				if errors.Is(err, windows.ERROR_SERVICE_EXISTS) {
					service, _ = windows.OpenService(manager, pdevice, windows.SERVICE_ALL_ACCESS)
				} else {
					return err
				}
			}
		} else {
			return err
		}
	}
	defer windows.CloseServiceHandle(service)

	// Register event logging:
	_ = winDivertRegisterEventSource(sysPath)

	err = windows.StartService(service, 0, nil)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_ALREADY_RUNNING) {
		} else {
			return err
		}
	}

	// 当前service是running状态, 不会立即删除, 只有当电脑重启
	// 或者service变为stopped状态时才会删除（延时删除）
	windows.DeleteService(service)
	return nil
}

func _WinDivertDriverUninstall() error {
	if installed, err := winDivertDriverInstalled(); err != nil {
		return err
	} else if !installed {
		return nil
	}
	mu, err := winDivertDriverMutex()
	if err != nil {
		return err
	}
	if err := mu.Lock(); err != nil {
		return err
	}
	defer mu.Unlock()

	// Open the service manager:
	manager, err := windows.OpenSCManager(nil, nil, windows.SC_MANAGER_ALL_ACCESS)
	if err != nil {
		return err
	}
	defer windows.CloseServiceHandle(manager)

	pdevice, err := windows.UTF16PtrFromString(WINDIVERT_DEVICE_NAME)
	if err != nil {
		return err
	}
	service, err := windows.OpenService(manager, pdevice, windows.SERVICE_ALL_ACCESS)
	if err != nil {
		if errors.Is(err, windows.ERROR_SERVICE_DOES_NOT_EXIST) {
			return nil
		} else {
			return err
		}
	}
	defer windows.CloseServiceHandle(service)

	err = windows.ControlService(service, windows.SERVICE_CONTROL_STOP, &windows.SERVICE_STATUS{})
	if err != nil {
		return err
	}

	var status = &windows.SERVICE_STATUS{}
	for {
		if err := windows.QueryServiceStatus(service, status); err != nil {
			return err
		}
		if status.CurrentState == windows.SERVICE_STOPPED {
			break
		}
		time.Sleep(time.Second)
	}
	return windows.DeleteService(service)
}

type driverMutex windows.Handle

func winDivertDriverMutex() (driverMutex, error) {
	// Create a named mutex.  This is to stop two processes trying
	// to start the driver at the same time.
	pmu, err := windows.UTF16PtrFromString(WinDivertDriverInstallMutex)
	if err != nil {
		return 0, err
	}
	mutex, err := windows.CreateMutex(nil, false, pmu)
	if err != nil {
		return 0, err
	}
	return driverMutex(mutex), nil
}
func (m driverMutex) Lock() error {
	event, err := windows.WaitForSingleObject(windows.Handle(m), windows.INFINITE)
	if err != nil {
		return err
	} else if event != windows.WAIT_OBJECT_0 && event != windows.WAIT_ABANDONED {
		return errors.Errorf("WaitForSingleObject event %d", event)
	}
	return nil
}
func (m driverMutex) Unlock() {
	windows.ReleaseMutex(windows.Handle(m))
	windows.Close(windows.Handle(m))
}

func winDivertDriverInstalled() (installed bool, err error) {
	pname, err := windows.UTF16PtrFromString(fmt.Sprintf("\\\\.\\%s", WINDIVERT_DEVICE_NAME))
	if err != nil {
		return false, err
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
	if err != nil {
		if errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
			errors.Is(err, windows.ERROR_PATH_NOT_FOUND) {

			return false, nil
		} else {
			return false, err
		}

	}
	defer windows.Close(h)

	return true, nil
}

// todo
func winDivertRegisterEventSource(sysPath string) error {
	// windows.RegisterEventSource()
	_ = sysPath
	return nil
}
