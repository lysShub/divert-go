//go:build windows
// +build windows

package divert

import (
	"github.com/lysShub/go-dll"
)

// todo: support ctx
type Divert struct {
	handle uintptr

	divertDll dll.DLL

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

func LoadDivert[T string | dll.MemDLL](b T) (*Divert, error) {
	var err error
	var d = &Divert{}

	d.divertDll, err = dll.LoadDLL(b)
	if err == nil {
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

	return d, err
}
