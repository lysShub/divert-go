package divert

import (
	"syscall"
	"unsafe"
)

func HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := divert.HelperCompileFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	if r1 == 0 {
		return "", err
	}

	for i, v := range buf {
		if v == 0 {
			return string(buf[:i]), nil
		}
	}
	return "", nil
}

func HelperEvalFilter(filter string, packet []byte, addr *Address) (bool, error) {
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

func HelperFormatFilter(filter string, layer Layer) (string, error) {
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
