//go:build windows
// +build windows

package divert

import (
	"syscall"
	"unsafe"

	"github.com/lysShub/divert-go/dll"
	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var (
	divert = dll.NewLazyDLL("WinDivert.dll")

	procOpen                = divert.NewProc("WinDivertOpen")
	procHelperCompileFilter = divert.NewProc("WinDivertHelperCompileFilter")
	procHelperEvalFilter    = divert.NewProc("WinDivertHelperEvalFilter")
	procHelperFormatFilter  = divert.NewProc("WinDivertHelperFormatFilter")

	procRecv     = divert.NewProc("WinDivertRecv")
	procRecvEx   = divert.NewProc("WinDivertRecvEx")
	procSend     = divert.NewProc("WinDivertSend")
	procSendEx   = divert.NewProc("WinDivertSendEx")
	procShutdown = divert.NewProc("WinDivertShutdown")
	procClose    = divert.NewProc("WinDivertClose")
	procSetParam = divert.NewProc("WinDivertSetParam")
	procGetParam = divert.NewProc("WinDivertGetParam")
)

func MustLoad[T string | Mem](p T) struct{} {
	err := Load(p)
	if err != nil && !errors.Is(err, ErrLoaded{}) {
		panic(err)
	}
	return struct{}{}
}

func Load[T string | Mem](p T) error {
	if divert.Loaded() {
		return ErrLoaded{}
	}

	switch p := any(p).(type) {
	case string:
		dll.ResetLazyDll(divert, p)
	case Mem:
		if err := driverInstall(p.Sys); err != nil {
			return errors.WithStack(err)
		}
		dll.ResetLazyDll(divert, p.DLL)
	default:
		panic("")
	}
	return nil
}

func Open(filter string, layer Layer, priority int16, flags Flag) (*Handle, error) {
	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	// flags = flags | NoInstall
	r1, _, e := syscall.SyscallN(
		procOpen.Addr(),
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == uintptr(windows.InvalidHandle) || e != 0 {
		return nil, errors.WithStack(e)
	}

	return &Handle{
		handle:   r1,
		layer:    layer,
		priority: priority,
	}, nil
}

func HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf = make([]byte, len(filter)+64)
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}

	r1, _, e := syscall.SyscallN(
		procHelperCompileFilter.Addr(),
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

	r1, _, e := syscall.SyscallN(
		procHelperEvalFilter.Addr(),
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

	r1, _, e := syscall.SyscallN(
		procHelperFormatFilter.Addr(),
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
