//go:build windows
// +build windows

package divert

import (
	"context"
	"fmt"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

type Handle struct {
	handle uintptr

	events    events
	layer     Layer
	priority  int16
	ctxPeriod uint32 // milliseconds
}

type events struct {
	mu sync.RWMutex
	s  []windows.Handle
}

func (g *events) get() (windows.Handle, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(g.s) == 0 {
		return windows.CreateEvent(nil, 0, 0, nil)
	} else {
		defer func() { g.s = g.s[:len(g.s)-1] }()
		return g.s[len(g.s)-1], nil
	}
}

func (g *events) put(h windows.Handle) error {
	if err := windows.ResetEvent(h); err != nil {
		return err
	}
	g.mu.Lock()
	defer g.mu.Unlock()

	g.s = append(g.s, h)
	return nil
}

func (g *events) close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	var err error
	for _, e := range g.s {
		e := windows.CloseHandle(e)
		if e != nil && err == nil {
			err = e
		}
	}
	return err
}

func (d *Handle) Close() error {
	r1, _, e := global.calln(
		global.procClose,
		d.handle,
	)
	if r1 == 0 {
		return handleError(e)
	}
	return handleError(d.events.close())
}
func (d *Handle) Priority() int16 { return d.priority }

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
		n := len(ip)
		if n > 20 {
			n = 20
		}
		fmt.Printf("%#v", ip[:n])
		fmt.Println("msg", len(ip), header.IPv4(ip).TotalLength())

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
	for {
		n, err = d.recvCtx(ctx, ip, addr)
		if err != windows.ERROR_NO_DATA {
			return n, err
		}
	}
}
func (d *Handle) recvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	dataMode := d.layer.dataLayer()
	if dataMode && len(ip) == 0 {
		return 0, handleError(windows.ERROR_INVALID_PARAMETER)
	} else if !dataMode && addr == nil {
		return 0, handleError(windows.ERROR_INVALID_PARAMETER)
	}

	var ol = &windows.Overlapped{}
	ol.HEvent, err = d.events.get()
	if err != nil {
		return 0, handleError(err)
	}
	defer d.events.put(ol.HEvent)

	ip[0] = 0
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
				if err != nil && err != windows.ERROR_NOT_FOUND {
					return 0, errors.WithStack(err)
				}
				return 0, handleError(ctx.Err())
			default:
				continue
			}
		case windows.WAIT_OBJECT_0:
			if dataMode {
				if ip[0] == 0 {
					return 0, windows.ERROR_NO_DATA
				}

				// GetOverlappedResult not work expectly, if bWait==true, possible wait always,
				// if bWait==false, possible get 0/ERROR_IO_INCOMPLETE.
				return getlen(ip)
			} else {
				return 0, nil
			}
		default:
			return 0, errors.WithMessagef(err, "unexpect WaitForSingleObject event 0x%08x", e)
		}
	}
}

func getlen(ip []byte) (n int, err error) {
	switch header.IPVersion(ip) {
	case 4:
		n = int(header.IPv4(ip).TotalLength())
	case 6:
		n = int(header.IPv6(ip).PayloadLength()) + header.IPv6FixedHeaderSize
	default:
		return 0, errors.New("invalid ip packet")
	}
	if n > len(ip) {
		return 0, errors.WithStack(windows.ERROR_INSUFFICIENT_BUFFER)
	}
	return n, nil
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
