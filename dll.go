//go:build windows
// +build windows

package divert

import (
	"sync"
	"sync/atomic"

	"github.com/lysShub/dll-go"
)

var divert = struct {
	refs atomic.Int32

	sync.RWMutex
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
	divert.Lock()
	defer divert.Unlock()
	defer func() {
		if err != nil {
			initDivertLocked()
		}
	}()

	if divert.dll != nil {
		return nil
	} else {
		if err = driverInstall(driver); err != nil {
			return err
		}
		if divert.dll, err = dll.LoadDLL(b); err != nil {
			return err
		}

		if divert.openProc, err = divert.dll.FindProc("WinDivertOpen"); err != nil {
			return err
		}
		if divert.recvProc, err = divert.dll.FindProc("WinDivertRecv"); err != nil {
			return err
		}
		if divert.recvExProc, err = divert.dll.FindProc("WinDivertRecvEx"); err != nil {
			return err
		}
		if divert.sendProc, err = divert.dll.FindProc("WinDivertSend"); err != nil {
			return err
		}
		if divert.sendExProc, err = divert.dll.FindProc("WinDivertSendEx"); err != nil {
			return err
		}
		if divert.shutdownProc, err = divert.dll.FindProc("WinDivertShutdown"); err != nil {
			return err
		}
		if divert.closeProc, err = divert.dll.FindProc("WinDivertClose"); err != nil {
			return err
		}
		if divert.setParamProc, err = divert.dll.FindProc("WinDivertSetParam"); err != nil {
			return err
		}
		if divert.getParamProc, err = divert.dll.FindProc("WinDivertGetParam"); err != nil {
			return err
		}

		if divert.helperCompileFilterProc, err = divert.dll.FindProc("WinDivertHelperCompileFilter"); err != nil {
			return err
		}
		if divert.helperEvalFilterProc, err = divert.dll.FindProc("WinDivertHelperEvalFilter"); err != nil {
			return err
		}
		if divert.helperFormatFilterProc, err = divert.dll.FindProc("WinDivertHelperFormatFilter"); err != nil {
			return err
		}
	}

	return nil
}

func Release() error {
	divert.Lock()
	defer divert.Unlock()

	if divert.dll == nil {
		return dll.ERR_RELEASE_DLL_NOT_LOAD
	}
	if divert.refs.Load() > 0 {
		return dll.ERR_RELEASE_DLL_IN_USE
	}

	if err := divert.dll.Release(); err != nil {
		return err
	}

	initDivertLocked()
	return nil
}

func initDivertLocked() {
	divert.refs.Store(0)
	// divert.RWMutex = sync.RWMutex{}
	divert.dll = nil
	divert.openProc = 0
	divert.recvProc = 0
	divert.recvExProc = 0
	divert.sendProc = 0
	divert.sendExProc = 0
	divert.shutdownProc = 0
	divert.closeProc = 0
	divert.setParamProc = 0
	divert.getParamProc = 0
	divert.helperCompileFilterProc = 0
	divert.helperEvalFilterProc = 0
	divert.helperFormatFilterProc = 0
}
