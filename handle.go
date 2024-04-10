//go:build windows
// +build windows

package divert

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type Handle struct {
	handle    uintptr
	layer     Layer
	ctxPeriod uint32 // milliseconds
}

func (d *Handle) Close() error {
	r1, _, e := global.calln(
		global.procClose,
		d.handle,
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) SetCtxPeriod(milliseconds uint32) {
	d.ctxPeriod = milliseconds
	if d.ctxPeriod < 5 {
		d.ctxPeriod = 5
	}
}

func (d *Handle) Recv(ip []byte, addr *Address) (int, error) {
	var recvLen uint32
	var dataPtr, recvLenPtr uintptr
	if len(ip) > 0 {
		dataPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	r1, _, e := global.calln(
		global.procRecv,
		d.handle,
		dataPtr,
		uintptr(len(ip)),
		recvLenPtr,
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, handleError(e)
	}

	return int(recvLen), nil
}

// RecvEx
// notice: recvLen not work, use windows.GetOverlappedResult
// todo: support batch recv
func (d *Handle) RecvEx(ip []byte, addr *Address, recvLen *uint32, ol *windows.Overlapped) error {
	err := d.recvEx(ip, addr, recvLen, ol)
	if err != nil {
		return handleError(err)
	}
	return nil
}

func (d *Handle) recvEx(ip []byte, addr *Address, recvLen *uint32, ol *windows.Overlapped) error {
	var ipPtr uintptr
	if len(ip) > 0 {
		ipPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	}

	r1, _, e := global.calln(
		global.procRecvEx,
		d.handle,
		ipPtr,                            // pPacket
		uintptr(len(ip)),                 // packetLen
		uintptr(unsafe.Pointer(recvLen)), // pRecvLen  NOTICE: not work
		uintptr(0),                       // flags 0
		uintptr(unsafe.Pointer(addr)),    // pAddr
		0,                                // pAddrLen
		uintptr(unsafe.Pointer(ol)),      // lpOverlapped
	)
	if r1 == 0 {
		return e
	}
	return nil
}

func (d *Handle) RecvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	dataMode := d.layer.dataLayer()
	if dataMode && len(ip) == 0 {
		return 0, handleError(windows.ERROR_INVALID_PARAMETER)
	} else if !dataMode && addr == nil {
		return 0, handleError(windows.ERROR_INVALID_PARAMETER)
	}

	var ol = &windows.Overlapped{}
	ol.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, handleError(err)
	}
	defer windows.CloseHandle(ol.HEvent)

	err = d.recvEx(ip, addr, nil, ol)
	if err == syscall.ERROR_IO_PENDING {
		if err != nil {
			return 0, errors.New("expect ERROR_IO_PENDING")
		}
		return 0, handleError(err)
	}

	for {
		e, err := windows.WaitForSingleObject(ol.HEvent, d.ctxPeriod)
		if err != nil {
			return 0, errors.WithStack(err)
		}

		switch e {
		case uint32(windows.WAIT_TIMEOUT):
			select {
			case <-ctx.Done():
				err = windows.CancelIoEx(windows.Handle(d.handle), ol)
				if err != nil {
					return 0, errors.WithStack(err)
				}
				return 0, handleError(ctx.Err())
			default:
				continue
			}
		case windows.WAIT_OBJECT_0:
			var m uint32
			err := windows.GetOverlappedResult(windows.Handle(d.handle), ol, &m, true)
			if err != nil {
				return 0, errors.WithStack(err)
			}
			if m == 0 && dataMode {
				return 0, errors.New("recv zero bytes data")
			}
			return int(m), nil
		default:
			return 0, errors.WithMessagef(err, "unexpect WaitForSingleObject event 0x%08x", e)
		}
	}
}

func (d *Handle) Send(ip []byte, addr *Address) (int, error) {
	if len(ip) == 0 {
		return 0, nil
	}

	var n uint32
	r1, _, e := global.calln(
		global.procSend,
		d.handle, // handle
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
	r1, _, e := global.calln(
		global.procSendEx,
		d.handle,
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
	r1, _, e := global.calln(
		global.procShutdown,
		d.handle,
		uintptr(how),
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) SetParam(param PARAM, value uint64) error {
	r1, _, e := global.calln(
		global.procSetParam,
		d.handle,
		uintptr(param),
		uintptr(value),
	)
	if r1 == 0 {
		return handleError(e)
	}
	return nil
}

func (d *Handle) GetParam(param PARAM) (value uint64, err error) {
	r1, _, e := global.calln(
		global.procGetParam,
		d.handle,
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
