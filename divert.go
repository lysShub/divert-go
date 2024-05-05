//go:build windows
// +build windows

package divert

import (
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var global divert

func MustLoad[T string | Mem](p T) struct{} {
	err := Load(p)
	if err != nil && !errors.Is(err, ErrLoaded{}) {
		panic(err)
	}
	return struct{}{}
}

func Load[T string | Mem](p T) error {
	global.Lock()
	defer global.Unlock()
	if global.dll != nil {
		return ErrLoaded{}
	}

	var err error
	switch p := any(p).(type) {
	case string:
		global.dll, err = loadFileDLL(p)
		if err != nil {
			return errors.WithStack(err)
		}
	case Mem:
		if err = driverInstall(p.Sys); err != nil {
			return errors.WithStack(err)
		}

		global.dll, err = loadMemDLL(p.DLL)
		if err != nil {
			return err
		}
	default:
		return windows.ERROR_INVALID_PARAMETER
	}

	err = global.init()
	return errors.WithStack(err)
}

func Release() error {
	global.Lock()
	defer global.Unlock()
	if global.dll == nil {
		return nil
	}

	err := global.dll.Release()
	global.dll = nil
	return errors.WithStack(err)
}

type divert struct {
	sync.RWMutex
	dll dll

	procOpen                uintptr // WinDivertOpen
	procHelperCompileFilter uintptr // WinDivertHelperCompileFilter
	procHelperEvalFilter    uintptr // WinDivertHelperEvalFilter
	procHelperFormatFilter  uintptr // WinDivertHelperFormatFilter

	procRecv     uintptr // WinDivertRecv
	procRecvEx   uintptr // WinDivertRecvEx
	procSend     uintptr // WinDivertSend
	procSendEx   uintptr // WinDivertSendEx
	procShutdown uintptr // WinDivertShutdown
	procClose    uintptr // WinDivertClose
	procSetParam uintptr // WinDivertSetParam
	procGetParam uintptr // WinDivertGetParam
}

func (d *divert) init() (err error) {
	if d.procOpen, err = d.dll.FindProc("WinDivertOpen"); err != nil {
		goto ret
	}
	if d.procHelperCompileFilter, err = d.dll.FindProc("WinDivertHelperCompileFilter"); err != nil {
		goto ret
	}
	if d.procHelperEvalFilter, err = d.dll.FindProc("WinDivertHelperEvalFilter"); err != nil {
		goto ret
	}
	if d.procHelperFormatFilter, err = d.dll.FindProc("WinDivertHelperFormatFilter"); err != nil {
		goto ret
	}

	if d.procRecv, err = d.dll.FindProc("WinDivertRecv"); err != nil {
		goto ret
	}
	if d.procRecvEx, err = d.dll.FindProc("WinDivertRecvEx"); err != nil {
		goto ret
	}
	if d.procSend, err = d.dll.FindProc("WinDivertSend"); err != nil {
		goto ret
	}
	if d.procSendEx, err = d.dll.FindProc("WinDivertSendEx"); err != nil {
		goto ret
	}
	if d.procShutdown, err = d.dll.FindProc("WinDivertShutdown"); err != nil {
		goto ret
	}
	if d.procClose, err = d.dll.FindProc("WinDivertClose"); err != nil {
		goto ret
	}
	if d.procSetParam, err = d.dll.FindProc("WinDivertSetParam"); err != nil {
		goto ret
	}
	if d.procGetParam, err = d.dll.FindProc("WinDivertGetParam"); err != nil {
		goto ret
	}

ret:
	if err != nil {
		d.dll.Release()
		d.dll = nil
	}
	return err
}

func (d *divert) calln(trap uintptr, args ...uintptr) (r1, r2 uintptr, err error) {
	d.RLock()
	defer d.RUnlock()
	if d.dll == nil || trap == 0 {
		return 0, 0, errors.WithStack(ErrNotLoad{})
	}

	var e syscall.Errno
	r1, r2, e = syscall.SyscallN(trap, args...)
	if e == windows.ERROR_SUCCESS {
		return r1, r2, nil
	}

	return r1, r2, errors.WithStack(e)
}

func Open(filter string, layer Layer, priority int16, flags Flag) (*Handle, error) {
	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	// flags = flags | NoInstall
	r1, _, e := global.calln(
		global.procOpen,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == uintptr(windows.InvalidHandle) || e != nil {
		return nil, errors.WithStack(e)
	}

	return &Handle{
		handle:    r1,
		layer:     layer,
		priority:  priority,
		ctxPeriod: 100,
	}, nil
}

func HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf = make([]byte, len(filter)+64)
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}

	r1, _, e := global.calln(
		global.procHelperCompileFilter,
		uintptr(unsafe.Pointer(pFilter)),               // filter
		uintptr(layer),                                 // layer
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), // object
		uintptr(len(buf)),                              // objLen
		0,                                              // errorStr
		0,                                              // errorPos
	)
	if r1 == 0 {
		return "", errors.WithStack(e)
	}
	return windows.ByteSliceToString(buf), nil
}

func HelperEvalFilter(filter string, ip []byte, addr *Address) (bool, error) {
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}

	r1, _, e := global.calln(
		global.procHelperEvalFilter,
		uintptr(unsafe.Pointer(pFilter)),              // filter
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))), // pPacket
		uintptr(len(ip)),                              // packetLen
		uintptr(unsafe.Pointer(addr)),                 // pAddr
	)
	if r1 == 0 {
		return false, errors.WithStack(e)
	}
	return true, nil
}

func HelperFormatFilter(filter string, layer Layer) (string, error) {
	var buf = make([]uint8, len(filter)+64)
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}

	r1, _, e := global.calln(
		global.procHelperFormatFilter,
		uintptr(unsafe.Pointer(pFilter)),               // filter
		uintptr(layer),                                 // layer
		uintptr(unsafe.Pointer(unsafe.SliceData(buf))), // buffer
		uintptr(len(buf)),                              // bufLen
	)
	if r1 == 0 {
		return "", errors.WithStack(e)
	}
	return windows.ByteSliceToString(buf), nil
}
