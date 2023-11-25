//go:build windows
// +build windows

package divert

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Handle windows.Handle

func Open(filter string, layer Layer, priority int16, flags Flag) (hdl Handle, err error) {
	once.Do(func() { err = divert.init() })
	if err != nil {
		return INVALID_HANDLE_VALUE, err
	}

	if priority > WINDIVERT_PRIORITY_HIGHEST || priority < -WINDIVERT_PRIORITY_HIGHEST {
		return INVALID_HANDLE_VALUE, errors.New("priority out of range [-30000, 30000]")
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return INVALID_HANDLE_VALUE, err
	}

	r1, _, err := syscall.SyscallN(
		divert.OpenProc.Addr(),
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if Handle(r1) == INVALID_HANDLE_VALUE {
		return INVALID_HANDLE_VALUE, err
	}
	return Handle(r1), nil
}

func (h Handle) Recv(packet []byte) (int, Address, error) {
	var recvLen uint32
	var addr Address

	var sp, recvLenPtr uintptr
	if len(packet) > 0 {
		sp = uintptr(unsafe.Pointer(unsafe.SliceData(packet)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	r1, _, err := syscall.SyscallN(
		divert.RecvProc.Addr(),
		uintptr(h),
		sp,
		uintptr(len(packet)),
		uintptr(recvLenPtr),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		return 0, addr, err
	}
	return int(recvLen), addr, nil
}

type OVERLAPPED windows.Overlapped
type LPOVERLAPPED *OVERLAPPED

func (h Handle) RecvEx(
	packet []byte, flag uint64,
	lpOverlapped LPOVERLAPPED,
) (int, Address, error) {

	var recvLen uint32
	var addr Address
	r1, _, err := syscall.SyscallN(
		divert.RecvExProc.Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(unsafe.SliceData(packet))),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addr._size)),
		uintptr(unsafe.Pointer(lpOverlapped)),
	)
	if r1 == 0 {
		return 0, addr, err
	}
	return int(recvLen), addr, nil
}

func (h Handle) Send(
	packet []byte,
	pAddr *Address,
) (int, error) {

	var pSendLen uint32
	r1, _, err := syscall.SyscallN(
		divert.SendProc.Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(unsafe.SliceData(packet))),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(unsafe.Pointer(pAddr)),
	)

	if r1 == 0 {
		return 0, err
	}
	return int(pSendLen), nil
}

func (h Handle) SendEx(
	packet []byte, flag uint64,
	pAddr *Address,
) (int, LPOVERLAPPED, error) {

	var pSendLen uint32
	var overlapped OVERLAPPED

	r1, _, err := syscall.SyscallN(
		divert.SendExProc.Addr(),
		uintptr(h),
		uintptr(unsafe.Pointer(unsafe.SliceData(packet))),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(pAddr)),
		uintptr(pAddr._size),
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if r1 == 0 {
		return 0, nil, err
	}
	return int(pSendLen), &overlapped, nil
}

func (h Handle) Shutdown(how SHUTDOWN) error {
	r1, _, err := syscall.SyscallN(divert.ShutdownProc.Addr(), uintptr(h), uintptr(how))
	if r1 == 0 {
		return err
	}
	return nil
}

func (h Handle) Close() error {
	r1, _, err := syscall.SyscallN(divert.CloseProc.Addr(), uintptr(h))
	if r1 == 0 {
		return err
	}
	return nil
}

func (h Handle) SetParam(param PARAM, value uint64) error {
	r1, _, err := syscall.SyscallN(divert.SetParamProc.Addr(), uintptr(h), uintptr(param), uintptr(value))
	if r1 == 0 {
		return err
	}
	return nil
}

func (h Handle) GetParamProc(param PARAM) (value uint64, err error) {
	r1, _, err := syscall.SyscallN(divert.GetParamProc.Addr(), uintptr(h), uintptr(param), uintptr(unsafe.Pointer(&value)))
	if r1 == 0 {
		return 0, err
	}
	return value, nil
}

func HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := syscall.SyscallN(
		divert.HelperCompileFilterProc.Addr(),
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
	r1, _, err := syscall.SyscallN(
		divert.HelperEvalFilterProc.Addr(),
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
	var buf = make([]uint8, 1024)

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := syscall.SyscallN(
		divert.HelperFormatFilterProc.Addr(),
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", err
	}

	for i, v := range buf {
		if v == 0 {
			buf = buf[0:i]
			break
		}
	}
	return string(buf), nil
}
