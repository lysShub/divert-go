//go:build windows
// +build windows

package divert

import (
	"io"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Divert struct {
	dll    *DivertDLL
	handle uintptr
}

// Recv receive (read) a packet from a WinDivert handle.
func (d *Divert) Recv(packet []byte) (int, *Address, error) {
	var recvLen uint32
	var addr Address

	var sp, recvLenPtr uintptr
	if len(packet) > 0 {
		sp = uintptr(unsafe.Pointer(unsafe.SliceData(packet)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	r1, _, err := syscall.SyscallN(
		d.dll.recvProc,
		d.handle,
		sp,
		uintptr(len(packet)),
		uintptr(recvLenPtr),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		return 0, nil, handleRecvErr(err)
	}
	return int(recvLen), &addr, nil
}

// RecvEx receive (read) a packet from a WinDivert handle.
func (d *Divert) RecvEx(
	packet []byte, flag uint64,
	lpOverlapped *windows.Overlapped,
) (int, *Address, error) {

	var recvLen uint32
	var addr Address
	r1, _, err := syscall.SyscallN(
		d.dll.recvExProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(packet))),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(lpOverlapped)),
	)
	if r1 == 0 {
		return 0, nil, handleRecvErr(err)
	}
	return int(recvLen), &addr, nil
}

func handleRecvErr(err syscall.Errno) error {
	switch err {
	case windows.ERROR_OPERATION_ABORTED, // close after Recv()
		windows.ERROR_INVALID_HANDLE: // close before Recv()
		return net.ErrClosed
	case windows.ERROR_NO_DATA:
		return nil // shutdown
	case windows.ERROR_INSUFFICIENT_BUFFER:
		return io.ErrShortBuffer
	default:
		return err
	}
}

func (d *Divert) Send(
	packet []byte,
	pAddr *Address,
) (int, error) {

	var pSendLen uint32
	r1, _, err := syscall.SyscallN(
		d.dll.sendProc,
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

// SendEx send (write/inject) a packet to a WinDivert handle.
func (d *Divert) SendEx(
	packet []byte, flag uint64,
	pAddr *Address,
) (int, *windows.Overlapped, error) {

	var pSendLen uint32
	var overlapped windows.Overlapped

	r1, _, err := syscall.SyscallN(
		d.dll.sendExProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(packet))),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(pAddr)),
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if r1 == 0 {
		return 0, nil, err
	}
	return int(pSendLen), &overlapped, nil
}

func (d *Divert) Shutdown(how SHUTDOWN) error {
	r1, _, err := syscall.SyscallN(d.dll.shutdownProc, d.handle, uintptr(how))
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Divert) Close() error {
	r1, _, err := syscall.SyscallN(d.dll.closeProc, d.handle)
	if r1 == 0 {
		if err == windows.ERROR_INVALID_HANDLE {
			return net.ErrClosed
		}
		return err
	}

	d.dll.refsMu.Lock()
	defer d.dll.refsMu.Unlock()
	d.dll.refs--

	return nil
}

func (d *Divert) SetParam(param PARAM, value uint64) error {
	r1, _, err := syscall.SyscallN(d.dll.setParamProc, d.handle, uintptr(param), uintptr(value))
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Divert) GetParam(param PARAM) (value uint64, err error) {
	r1, _, err := syscall.SyscallN(d.dll.getParamProc, d.handle, uintptr(param), uintptr(unsafe.Pointer(&value)))
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
		d.dll.helperCompileFilterProc,
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
		d.dll.helperEvalFilterProc,
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
		d.dll.helperFormatFilterProc,
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
