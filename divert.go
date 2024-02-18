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
func (d *Divert) Recv(ip []byte, addr *Address) (int, error) {
	var recvLen uint32

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
		uintptr(unsafe.Pointer(addr)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, handleErr(err)
	}
	return int(recvLen), nil
}

// RecvEx receive (read) a ip packet from a WinDivert handle.
func (d *Divert) RecvEx(
	ip []byte,
	addr *Address,
	ol *windows.Overlapped,
) error {

	var ipPtr uintptr
	if len(ip) > 0 {
		ipPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	}

	divert.RLock()
	r1, _, err := syscallN(
		divert.recvExProc,
		d.handle,
		ipPtr,                         // pPacket
		uintptr(len(ip)),              // packetLen
		0,                             // pRecvLen  NOTICE: not work
		uintptr(0),                    // flags 0
		uintptr(unsafe.Pointer(addr)), // pAddr
		0,                             // pAddrLen
		uintptr(unsafe.Pointer(ol)),   // lpOverlapped
	)
	divert.RUnlock()
	if !intbool(r1) {
		return handleErr(err)
	}
	return nil
}

func (d *Divert) RecvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	var ol = &windows.Overlapped{}
	ol.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.Close(ol.HEvent)

	err = d.RecvEx(ip, addr, ol)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return 0, err
	}

	for {
		e, err := windows.WaitForSingleObject(ol.HEvent, uint32(CtxCancelDelay.Milliseconds()))
		if err != nil {
			return 0, err
		}
		switch e {
		case windows.WAIT_OBJECT_0:
			var m uint32
			err = windows.GetOverlappedResult(windows.Handle(d.handle), ol, &m, false)
			if err != nil {
				return 0, err
			}
			return int(m), nil
		case uint32(windows.WAIT_TIMEOUT):
			select {
			case <-ctx.Done():
				return 0, ctx.Err()
			default:
			}
		default:
			return 0, fmt.Errorf("invalid WaitForSingleObject return %d", e)
		}
	}

}

func (d *Divert) Send(
	ip []byte,
	addr *Address,
) (int, error) {

	var pSendLen uint32
	divert.RLock()
	r1, _, err := syscallN(
		divert.sendProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(unsafe.Pointer(addr)),
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
	addr *Address,
	ol *windows.Overlapped,
) (int, error) {

	var pSendLen uint32

	divert.RLock()
	r1, _, err := syscallN(
		divert.sendExProc,
		d.handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(addr)),
		0,
		uintptr(unsafe.Pointer(ol)),
	)
	divert.RUnlock()
	if !intbool(r1) {
		return 0, handleErr(err)
	}

	return int(pSendLen), err
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
