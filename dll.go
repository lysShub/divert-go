//go:build windows
// +build windows

package divert

import (
	"errors"
	"sync"
	"syscall"
	"unsafe"

	"github.com/lysShub/go-dll"
	"golang.org/x/sys/windows"
)

// todo: support ctx
type DivertDLL struct {
	divertDll dll.DLL

	refs   int
	refsMu sync.Mutex

	openProc     uintptr // WinDivertOpen
	recvProc     uintptr // WinDivertRecv
	recvExProc   uintptr // WinDivertRecvEx
	sendProc     uintptr // WinDivertSend
	sendExProc   uintptr // WinDivertSendEx
	shutdownProc uintptr // WinDivertShutdown
	closeProc    uintptr // WinDivertClose
	setParamProc uintptr // WinDivertSetParam
	getParamProc uintptr // WinDivertGetParam

	helperCompileFilterProc uintptr // WinDivertHelperCompileFilter
	helperEvalFilterProc    uintptr // WinDivertHelperEvalFilter
	helperFormatFilterProc  uintptr // WinDivertHelperFormatFilter
}

func LoadDivert[T string | dll.MemDLL](b T, driver T) (*DivertDLL, error) {
	if err := driverInstall(driver); err != nil {
		return nil, err
	}

	var err error
	var d = &DivertDLL{}

	d.divertDll, err = dll.LoadDLL(b)
	if err != nil {
		return nil, err
	}

	if d.openProc, err = d.divertDll.FindProc("WinDivertOpen"); err != nil {
		return nil, err
	}
	if d.recvProc, err = d.divertDll.FindProc("WinDivertRecv"); err != nil {
		return nil, err
	}
	if d.recvExProc, err = d.divertDll.FindProc("WinDivertRecvEx"); err != nil {
		return nil, err
	}
	if d.sendProc, err = d.divertDll.FindProc("WinDivertSend"); err != nil {
		return nil, err
	}
	if d.sendExProc, err = d.divertDll.FindProc("WinDivertSendEx"); err != nil {
		return nil, err
	}
	if d.shutdownProc, err = d.divertDll.FindProc("WinDivertShutdown"); err != nil {
		return nil, err
	}
	if d.closeProc, err = d.divertDll.FindProc("WinDivertClose"); err != nil {
		return nil, err
	}
	if d.setParamProc, err = d.divertDll.FindProc("WinDivertSetParam"); err != nil {
		return nil, err
	}
	if d.getParamProc, err = d.divertDll.FindProc("WinDivertGetParam"); err != nil {
		return nil, err
	}

	if d.helperCompileFilterProc, err = d.divertDll.FindProc("WinDivertHelperCompileFilter"); err != nil {
		return nil, err
	}
	if d.helperEvalFilterProc, err = d.divertDll.FindProc("WinDivertHelperEvalFilter"); err != nil {
		return nil, err
	}
	if d.helperFormatFilterProc, err = d.divertDll.FindProc("WinDivertHelperFormatFilter"); err != nil {
		return nil, err
	}

	return d, nil
}

// Open open a WinDivert handle.
func (d *DivertDLL) Open(filter string, layer Layer, priority int16, flags Flag) (divert *Divert, err error) {
	d.refsMu.Lock()
	defer d.refsMu.Unlock()

	if priority > WINDIVERT_PRIORITY_HIGHEST || priority < -WINDIVERT_PRIORITY_HIGHEST {
		return nil, errors.New("priority out of range [-30000, 30000]")
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	flags = flags | NO_INSTALL
	r1, _, err := syscall.SyscallN(
		d.openProc,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == 0 || r1 == uintptr(windows.InvalidHandle) {
		return nil, err
	}

	d.refs++
	return &Divert{
		dll:    d,
		handle: r1,
	}, nil
}

func (d *DivertDLL) Release() error {
	d.refsMu.Lock()
	defer d.refsMu.Unlock()

	if d.refs == 0 {
		return d.divertDll.Release()
	} else {
		return nil
	}
}
