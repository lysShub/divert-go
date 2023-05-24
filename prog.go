package divert

import (
	"errors"
	"sync"

	"golang.org/x/sys/windows"
)

var _dllPath = `WinDivert.dll`

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

func (d *dll) init() (err error) {
	d.OpenProc, err = d.FindProc("WinDivertOpen")
	if err != nil {
		return err
	}
	d.RecvProc, err = d.FindProc("WinDivertRecv")
	if err != nil {
		return err
	}
	d.RecvExProc, err = d.FindProc("WinDivertRecvEx")
	if err != nil {
		return err
	}
	d.SendProc, err = d.FindProc("WinDivertSend")
	if err != nil {
		return err
	}
	d.SendExProc, err = d.FindProc("WinDivertSendEx")
	if err != nil {
		return err
	}
	d.ShutdownProc, err = d.FindProc("WinDivertShutdown")
	if err != nil {
		return err
	}
	d.CloseProc, err = d.FindProc("WinDivertClose")
	if err != nil {
		return err
	}
	d.SetParamProc, err = d.FindProc("WinDivertSetParam")
	if err != nil {
		return err
	}
	d.GetParamProc, err = d.FindProc("WinDivertGetParam")
	if err != nil {
		return err
	}

	d.HelperCompileFilterProc, err = d.FindProc("WinDivertHelperCompileFilter")
	if err != nil {
		return err
	}
	d.HelperEvalFilterProc, err = d.FindProc("WinDivertHelperEvalFilter")
	if err != nil {
		return err
	}
	d.HelperFormatFilterProc, err = d.FindProc("WinDivertHelperFormatFilter")
	if err != nil {
		return err
	}

	return nil
}

func SetPath(dllPath string) (err error) {
	_dllPath = dllPath

	divert.DLL, err = windows.LoadDLL(_dllPath)
	if err != nil {
		return err
	} else {
		return divert.init()
	}
}

func SetLib(lib *windows.DLL) error {
	if lib == nil {
		return errors.New("lib is nil")
	} else {
		once.Do(func() {})

		divert.DLL = lib
		return divert.init()
	}
}
