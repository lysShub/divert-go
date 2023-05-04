package divert

import (
	"syscall"
	"unsafe"
)

// var (
// 	divertHelperCompileFilterProc = divert.MustFindProc("WinDivertHelperCompileFilter")
// 	divertHelperEvalFilterProc    = divert.MustFindProc("WinDivertHelperEvalFilter")
// 	divertHelperFormatFilterProc  = divert.MustFindProc("WinDivertHelperFormatFilter")
// )

// Deprecated: un-understandable
func WinDivertHelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8
	var pErrorStr *uint8
	var errorPos uint32

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := divert.HelperCompileFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&pErrorStr)),
		uintptr(unsafe.Pointer(&errorPos)),
	)
	if r1 == 0 {
		return "", err
	}
	return string(buf[:]), nil
}

func WinDivertHelperEvalFilter(filter string, packet []byte, addr *Address) (bool, error) {
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}
	r1, _, err := divert.HelperEvalFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return false, err
	}
	return true, nil
}

func WinDivertHelperFormatFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := divert.HelperFormatFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", err
	}
	return string(buf[:]), nil
}
