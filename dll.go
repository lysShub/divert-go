//go:build windows
// +build windows

package divert

import (
	"fmt"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/lysShub/dll-go"
	"golang.org/x/sys/windows"
)

var divert = &struct {
	initOnce sync.Once
	refs     atomic.Int32

	dll dll.DLL

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
}{}

func MustLoad[T string | dll.MemDLL](dll T, driver T) {
	if err := Load(dll, driver); err != nil {
		panic(err)
	}
}

func Load[T string | dll.MemDLL](b T, driver T) (err error) {
	divert.initOnce.Do(func() {
		if err = driverInstall(driver); err != nil {
			return
		}
		if divert.dll, err = dll.LoadDLL(b); err != nil {
			return
		}

		if divert.openProc, err = divert.dll.FindProc("WinDivertOpen"); err != nil {
			return
		}
		if divert.recvProc, err = divert.dll.FindProc("WinDivertRecv"); err != nil {
			return
		}
		if divert.recvExProc, err = divert.dll.FindProc("WinDivertRecvEx"); err != nil {
			return
		}
		if divert.sendProc, err = divert.dll.FindProc("WinDivertSend"); err != nil {
			return
		}
		if divert.sendExProc, err = divert.dll.FindProc("WinDivertSendEx"); err != nil {
			return
		}
		if divert.shutdownProc, err = divert.dll.FindProc("WinDivertShutdown"); err != nil {
			return
		}
		if divert.closeProc, err = divert.dll.FindProc("WinDivertClose"); err != nil {
			return
		}
		if divert.setParamProc, err = divert.dll.FindProc("WinDivertSetParam"); err != nil {
			return
		}
		if divert.getParamProc, err = divert.dll.FindProc("WinDivertGetParam"); err != nil {
			return
		}

		if divert.helperCompileFilterProc, err = divert.dll.FindProc("WinDivertHelperCompileFilter"); err != nil {
			return
		}
		if divert.helperEvalFilterProc, err = divert.dll.FindProc("WinDivertHelperEvalFilter"); err != nil {
			return
		}
		if divert.helperFormatFilterProc, err = divert.dll.FindProc("WinDivertHelperFormatFilter"); err != nil {
			return
		}
	})

	if err != nil {
		divert.initOnce = sync.Once{}
	}
	return err
}

func Release() error {
	if divert.refs.CompareAndSwap(0, -1) {
		if divert.dll == nil { // not Load before
			divert.refs.Store(0)
			return nil
		}

		err := divert.dll.Release()
		if err == nil {
			divert = &struct {
				initOnce                sync.Once
				refs                    atomic.Int32
				dll                     dll.DLL
				openProc                uintptr
				recvProc                uintptr
				recvExProc              uintptr
				sendProc                uintptr
				sendExProc              uintptr
				shutdownProc            uintptr
				closeProc               uintptr
				setParamProc            uintptr
				getParamProc            uintptr
				helperCompileFilterProc uintptr
				helperEvalFilterProc    uintptr
				helperFormatFilterProc  uintptr
			}{}
		}
		return err
	}
	return fmt.Errorf("cannot release divert in use")
}

// Open open a WinDivert handle.
func Open(filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	if priority > PRIORITY_HIGHEST || priority < -PRIORITY_HIGHEST {
		return nil, fmt.Errorf("priority out of range [-%d, %d]", PRIORITY_HIGHEST, PRIORITY_HIGHEST)
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	flags = flags | NO_INSTALL
	r1, _, e := syscallN(
		divert.openProc,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == uintptr(syscall.InvalidHandle) || e != 0 {
		return nil, handleErr(e)
	}

	divert.refs.Add(1)
	return &Divert{
		handle: r1,
	}, nil
}
