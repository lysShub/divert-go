//go:build windows
// +build windows

package divert

import (
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type Handle struct {
	handle atomic.Uintptr

	layer    Layer
	priority int16
}

func (d *Handle) Close() error {
	const invalid = uintptr(windows.InvalidHandle)

	fd := d.handle.Swap(invalid)
	if fd != invalid {
		r1, _, e := syscall.SyscallN(
			procClose.Addr(),
			fd,
		)
		if r1 == 0 {
			return handleError(e)
		}
	}
	return ErrClosed{}
}
func (d *Handle) Priority() int16 { return d.priority }

// Recv recv ip packet, probable return 0.
func (d *Handle) Recv(ip []byte, addr *Address) (int, error) {
	var recvLen uint32
	r1, _, e := syscall.SyscallN(
		procRecv.Addr(),
		d.handle.Load(),
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, handleError(e)
	}

	return int(recvLen), nil
}

// RecvEx
// notice: recvLen not work, use windows.GetOverlappedResult
func (d *Handle) RecvEx(ip []byte, addr *Address, recvLen *uint32, ol *windows.Overlapped) error {
	// todo: support batch recv

	r1, _, e := syscall.SyscallN(
		procRecvEx.Addr(),
		d.handle.Load(),
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))), // pPacket
		uintptr(len(ip)),                 // packetLen
		uintptr(unsafe.Pointer(recvLen)), // pRecvLen  NOTICE: not work
		uintptr(0),                       // flags 0
		uintptr(unsafe.Pointer(addr)),    // pAddr
		0,                                // pAddrLen
		uintptr(unsafe.Pointer(ol)),      // lpOverlapped
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) Send(ip []byte, addr *Address) (int, error) {
	if len(ip) == 0 {
		return 0, nil
	}

	var n uint32
	r1, _, e := syscall.SyscallN(
		procSend.Addr(),
		d.handle.Load(),
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))), // pPacket
		uintptr(len(ip)),              // packetLen
		uintptr(unsafe.Pointer(&n)),   // pSendLen
		uintptr(unsafe.Pointer(addr)), // pAddr
	)
	if r1 == 0 {
		return 0, handleError(e)
	}
	return int(n), nil
}

func (d *Handle) SendEx(ip []byte, flag uint64, addr *Address, ol *windows.Overlapped) (int, error) {
	if len(ip) == 0 {
		return 0, nil
	}

	var n uint32

	// todo: support batch
	r1, _, e := syscall.SyscallN(
		procSendEx.Addr(),
		d.handle.Load(),
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))), // pPacket
		uintptr(len(ip)),              // packetLen
		uintptr(unsafe.Pointer(&n)),   // pSendLen
		uintptr(flag),                 // flags, always 0
		uintptr(unsafe.Pointer(addr)), // pAddr
		0,                             // addrLen
		uintptr(unsafe.Pointer(ol)),   // lpOverlapped
	)
	if r1 == 0 {
		return 0, handleError(e)
	}
	return int(n), nil
}

func (d *Handle) Shutdown(how Shutdown) error {
	r1, _, e := syscall.SyscallN(
		procShutdown.Addr(),
		d.handle.Load(),
		uintptr(how),
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) SetParam(param PARAM, value uint64) error {
	r1, _, e := syscall.SyscallN(
		procSetParam.Addr(),
		d.handle.Load(),
		uintptr(param),
		uintptr(value),
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) GetParam(param PARAM) (value uint64, err error) {
	r1, _, e := syscall.SyscallN(
		procGetParam.Addr(),
		d.handle.Load(),
		uintptr(param),
		uintptr(unsafe.Pointer(&value)),
	)
	if r1 == 0 {
		return 0, handleError(e)
	}
	return value, nil
}

func handleError(err error) error {
	if err != nil {
		if errors.Is(err, windows.ERROR_INVALID_HANDLE) ||
			errors.Is(err, windows.ERROR_OPERATION_ABORTED) {
			return errors.WithStack(ErrClosed{})
		} else if errors.Is(err, windows.ERROR_NO_DATA) {
			return errors.WithStack(ErrShutdown{})
		}

		return errors.WithStack(err)
	}
	return nil
}
