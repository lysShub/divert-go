//go:build windows
// +build windows

package divert

import (
	"errors"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (d *Divert) Open(filter string, layer Layer, priority int16, flags Flag) (err error) {
	if priority > WINDIVERT_PRIORITY_HIGHEST || priority < -WINDIVERT_PRIORITY_HIGHEST {
		return errors.New("priority out of range [-30000, 30000]")
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return err
	}

	r1, _, err := syscall.SyscallN(
		d.openProc,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == 0 {
		return err
	}
	d.handle = r1
	return nil
}

func (d *Divert) Recv(packet []byte) (int, Address, error) {
	var recvLen uint32
	var addr Address

	var sp, recvLenPtr uintptr
	if len(packet) > 0 {
		sp = uintptr(unsafe.Pointer(unsafe.SliceData(packet)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	r1, _, err := syscall.SyscallN(
		d.recvProc,
		d.handle,
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

func (d *Divert) RecvEx(
	packet []byte, flag uint64,
	lpOverlapped LPOVERLAPPED,
) (int, Address, error) {

	var recvLen uint32
	var addr Address
	r1, _, err := syscall.SyscallN(
		d.recvExProc,
		d.handle,
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

func (d *Divert) Send(
	packet []byte,
	pAddr *Address,
) (int, error) {

	var pSendLen uint32
	r1, _, err := syscall.SyscallN(
		d.sendProc,
		d.handle,
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

func (d *Divert) SendEx(
	packet []byte, flag uint64,
	pAddr *Address,
) (int, LPOVERLAPPED, error) {

	var pSendLen uint32
	var overlapped OVERLAPPED

	r1, _, err := syscall.SyscallN(
		d.sendExProc,
		d.handle,
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

func (d *Divert) Shutdown(how SHUTDOWN) error {
	r1, _, err := syscall.SyscallN(d.shutdownProc, d.handle, uintptr(how))
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Divert) Close() error {
	r1, _, err := syscall.SyscallN(d.closeProc, d.handle)
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Divert) SetParam(param PARAM, value uint64) error {
	r1, _, err := syscall.SyscallN(d.setParamProc, d.handle, uintptr(param), uintptr(value))
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Divert) GetParamProc(param PARAM) (value uint64, err error) {
	r1, _, err := syscall.SyscallN(d.getParamProc, d.handle, uintptr(param), uintptr(unsafe.Pointer(&value)))
	if r1 == 0 {
		return 0, err
	}
	return value, nil
}

func (d *Divert) HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := syscall.SyscallN(
		d.helperCompileFilterProc,
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

func (d *Divert) HelperEvalFilter(filter string, packet []byte, addr *Address) (bool, error) {
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}
	r1, _, err := syscall.SyscallN(
		d.helperEvalFilterProc,
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

func (d *Divert) HelperFormatFilter(filter string, layer Layer) (string, error) {
	var buf = make([]uint8, 1024)

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := syscall.SyscallN(
		d.helperFormatFilterProc,
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
