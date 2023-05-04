package divert

import (
	"errors"
	"sync"

	"golang.org/x/sys/windows"
)

var (
	_DLLPath = `WinDivert.dll`
)

var divert dll

type dll struct {
	*windows.DLL

	OpenProc     *windows.Proc // WinDivertOpen
	RecvProc     *windows.Proc // WinDivertRecv
	RecvExProc   *windows.Proc // WinDivertRecvEx
	SendProc     *windows.Proc // WinDivertSend
	SendExProc   *windows.Proc // WinDivertSendEx
	ShutdownProc *windows.Proc // WinDivertShutdown
	CloseProc    *windows.Proc // WinDivertClose
	SetParamProc *windows.Proc // WinDivertSetParam
	GetParamProc *windows.Proc // WinDivertGetParam

	HelperCompileFilterProc *windows.Proc // WinDivertHelperCompileFilter
	HelperEvalFilterProc    *windows.Proc // WinDivertHelperEvalFilter
	HelperFormatFilterProc  *windows.Proc // WinDivertHelperFormatFilter
}

var once sync.Once

func (d *dll) init() {
	d.OpenProc = d.MustFindProc("WinDivertOpen")
	d.RecvProc = d.MustFindProc("WinDivertRecv")
	d.RecvExProc = d.MustFindProc("WinDivertRecvEx")
	d.SendProc = d.MustFindProc("WinDivertSend")
	d.SendExProc = d.MustFindProc("WinDivertSendEx")
	d.ShutdownProc = d.MustFindProc("WinDivertShutdown")
	d.CloseProc = d.MustFindProc("WinDivertClose")
	d.SetParamProc = d.MustFindProc("WinDivertSetParam")
	d.GetParamProc = d.MustFindProc("WinDivertGetParam")

	d.HelperCompileFilterProc = d.MustFindProc("WinDivertHelperCompileFilter")
	d.HelperEvalFilterProc = d.MustFindProc("WinDivertHelperEvalFilter")
	d.HelperFormatFilterProc = d.MustFindProc("WinDivertHelperFormatFilter")
}

func SetPath(dllPath string) (err error) {
	_DLLPath = dllPath

	divert.DLL, err = windows.LoadDLL(_DLLPath)
	if err != nil {
		return err
	} else {
		divert.init()
		return nil
	}
}

func SetLib(lib *windows.DLL) error {
	if lib == nil {
		return errors.New("lib is nil")
	} else {
		once.Do(func() {})

		divert.DLL = lib
		divert.init()
		return nil
	}
}
