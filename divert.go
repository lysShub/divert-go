//go:build windows
// +build windows

package divert

import (
	"context"
	"fmt"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type Divert struct {
	handle uintptr
}

const defaultDelay = time.Millisecond * 100

var CtxCancelDelay time.Duration = defaultDelay

func init() {
	if CtxCancelDelay == 0 {
		CtxCancelDelay = defaultDelay
	}
}

func intbool[T uintptr | int](v T) bool {
	return v != 0
}

func handleErr(err syscall.Errno) error {
	switch err {
	case windows.ERROR_OPERATION_ABORTED, // close after Recv()
		windows.ERROR_INVALID_HANDLE: // close before Recv()

		return os.ErrClosed
	case windows.ERROR_NO_DATA:
		return nil // shutdown
	case windows.ERROR_INSUFFICIENT_BUFFER:
		return io.ErrShortBuffer
	default:
		if err == 0 {
			return syscall.EINVAL
		}
		return err
	}
}

// Open open a WinDivert handle.
func Open(filter string, layer Layer, priority int16, flags Flag) (*Divert, error) {
	if priority > PRIORITY_HIGHEST || priority < -PRIORITY_HIGHEST {
		return nil, fmt.Errorf("priority out of range [-%d, %d]", PRIORITY_HIGHEST, PRIORITY_HIGHEST)
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return nil, err
	}

	flags = flags | NO_INSTALL
	divert.RLock()
	r1, _, e := syscallN(
		divert.openProc,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	divert.RUnlock()
	if r1 == uintptr(syscall.InvalidHandle) || e != 0 {
		return nil, handleErr(e)
	}

	divert.refs.Add(1)
	return &Divert{
		handle: r1,
	}, nil
}

func (d *Divert) Close() error {
	old := atomic.SwapUintptr(&d.handle, 0)
	divert.RLock()
	r1, _, err := syscallN(divert.closeProc, old)
	divert.RUnlock()
	if !intbool(r1) {
		return handleErr(err)
	}

	divert.refs.Add(-1)
	return nil
}

// Recv receive (read) a ip packet from a WinDivert handle.
func (d *Divert) Recv(ip []byte) (int, *Address, error) {
	var recvLen uint32
	var addr Address

	var dataPtr, recvLenPtr uintptr
	if len(ip) > 0 {
		dataPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	divert.RLock()
	r1, _, err := syscallN(
		divert.recvProc,
		d.handle,
		dataPtr,
		uintptr(len(ip)),
		recvLenPtr,
		uintptr(unsafe.Pointer(&addr)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, nil, handleErr(err)
	}
	return int(recvLen), &addr, nil
}

// RecvEx receive (read) a ip packet from a WinDivert handle.
func (d *Divert) RecvEx(
	ip []byte, flag uint64,
	lpOverlapped *windows.Overlapped,
) (int, *Address, error) {

	var recvLen uint32
	var addr Address
	divert.RLock()
	r1, _, err := syscallN(
		divert.recvExProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(&addr)),
		0,
		uintptr(unsafe.Pointer(lpOverlapped)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, nil, handleErr(err)
	}
	return int(recvLen), &addr, nil
}

func (d *Divert) RecvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	var o windows.Overlapped
	var recvLen uint32

	o.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.Close(o.HEvent)

	for {

		divert.RLock()
		r1, _, err := syscallN(
			divert.recvExProc,
			d.handle,
			uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
			uintptr(len(ip)),
			uintptr(unsafe.Pointer(&recvLen)),
			0,
			uintptr(unsafe.Pointer(&addr)),
			0,
			uintptr(unsafe.Pointer(&o)),
		)
		divert.RUnlock()
		if !intbool(r1) && err != syscall.ERROR_IO_PENDING {
			return 0, handleErr(err)
		}

		wfd, e := windows.WaitForSingleObject(o.HEvent, uint32(CtxCancelDelay.Milliseconds()))
		if e != nil {
			return 0, e
		} else if wfd == windows.WAIT_OBJECT_0 {
			return int(recvLen), nil
		} else if wfd == uint32(windows.WAIT_TIMEOUT) {
			select {
			case <-ctx.Done():
				return 0, os.ErrDeadlineExceeded
			default:
			}
		} else {
			return 0, fmt.Errorf("invalid WaitForSingleObject return 0x%x", wfd)
		}
	}
}

func (d *Divert) Send(
	ip []byte,
	pAddr *Address,
) (int, error) {

	var pSendLen uint32
	divert.RLock()
	r1, _, err := syscallN(
		divert.sendProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(unsafe.Pointer(pAddr)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, handleErr(err)
	}
	return int(pSendLen), nil
}

// SendEx send (write/inject) a packet to a WinDivert handle.
func (d *Divert) SendEx(
	ip []byte, flag uint64,
	pAddr *Address,
) (int, *windows.Overlapped, error) {

	var pSendLen uint32
	var overlapped windows.Overlapped

	divert.RLock()
	r1, _, err := syscallN(
		divert.sendExProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(pAddr)),
		0,
		uintptr(unsafe.Pointer(&overlapped)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, nil, handleErr(err)
	}

	return int(pSendLen), &overlapped, err
}

func (d *Divert) Shutdown(how SHUTDOWN) error {
	divert.RLock()
	r1, _, err := syscallN(divert.shutdownProc, d.handle, uintptr(how))
	divert.RUnlock()
	if !intbool(r1) {
		return handleErr(err)
	}
	return nil
}

func (d *Divert) SetParam(param PARAM, value uint64) error {
	divert.RLock()
	r1, _, err := syscallN(divert.setParamProc, d.handle, uintptr(param), uintptr(value))
	divert.RUnlock()
	if !intbool(r1) {
		return handleErr(err)
	}
	return nil
}

func (d *Divert) GetParam(param PARAM) (value uint64, err error) {
	divert.RLock()
	r1, _, e := syscallN(
		divert.getParamProc,
		d.handle,
		uintptr(param),
		uintptr(unsafe.Pointer(&value)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, handleErr(e)
	}
	return value, nil
}

func (d *Divert) HelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf = make([]byte, len(filter)+64)

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	divert.RLock()
	r1, _, e := syscallN(
		divert.helperCompileFilterProc,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	divert.RUnlock()
	if !intbool(r1) {
		return "", handleErr(e)
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
	divert.RLock()
	r1, _, e := syscallN(
		divert.helperEvalFilterProc,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(addr)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return false, handleErr(e)
	}
	return true, e
}

func (d *Divert) HelperFormatFilter(filter string, layer Layer) (string, error) {
	var buf = make([]uint8, len(filter)+64)

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	divert.RLock()
	r1, _, e := syscallN(
		divert.helperFormatFilterProc,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return "", handleErr(e)
	}

	for i, v := range buf {
		if v == 0 {
			buf = buf[0:i]
			break
		}
	}
	return string(buf), nil
}
