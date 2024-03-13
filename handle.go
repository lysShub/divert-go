package divert

import (
	"context"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type Handle struct {
	handle uintptr
	layer  Layer
}

func (d *Handle) Close() error {
	err := global.close(d.handle)
	return errors.WithStack(err)
}

func (d *Handle) Recv(ip []byte, addr *Address) (int, error) {
	n, err := global.recv(d.handle, ip, addr)
	return n, errors.WithStack(err)
}

func (d *Handle) RecvEx(ip []byte, addr *Address, ol *windows.Overlapped) error {
	err := global.recvEx(d.handle, ip, addr, ol)
	return errors.WithStack(err)
}

func (d *Handle) RecvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	var ol = &windows.Overlapped{}
	ol.HEvent, err = windows.CreateEvent(nil, 0, 0, nil) // todo: use global event
	if err != nil {
		return 0, errors.WithStack(err)
	}
	defer windows.CloseHandle(ol.HEvent)

	if addr != nil {
		addr.Timestamp = 0
	}
	err = d.RecvEx(ip, addr, ol)
	if !errors.Is(err, syscall.ERROR_IO_PENDING) {
		if err == nil {
			return 0, errors.New("")
		}
		return 0, errors.WithStack(err)
	}

	var m uint32
	for i := 0; ; i++ {
		err := GetOverlappedResultEx(windows.Handle(d.handle), ol, &m, 100, false)
		if err == nil {
			notRecv := false
			if addr != nil {
				if addr.Timestamp == 0 {
					notRecv = true
				}
			} else {
				if m == 0 && d.layer.dataLayer() {
					notRecv = true
				}
			}
			if notRecv {
				return d.RecvCtx(ctx, ip, addr)
			}

			return int(m), nil
		} else {
			switch err {
			case windows.WAIT_TIMEOUT:
				select {
				case <-ctx.Done():
					err = windows.CancelIoEx(windows.Handle(d.handle), ol)
					if err != nil {
						return 0, errors.WithStack(err)
					}
					return 0, errors.WithStack(ctx.Err())
				default:
				}
			default:
				return 0, errors.WithStack(err)
			}
		}
	}
}

var (
	modkernel32               = windows.NewLazySystemDLL("kernel32.dll")
	procGetOverlappedResultEx = modkernel32.NewProc("GetOverlappedResultEx")
)

func GetOverlappedResultEx(
	handle windows.Handle, overlapped *windows.Overlapped,
	numberOfBytesTransferred *uint32,
	milliseconds uint32, alertable bool) error {

	var alert uintptr = 0 // false
	if alertable {
		alert = 1
	}

	r1, _, err := syscall.SyscallN(
		procGetOverlappedResultEx.Addr(),
		uintptr(handle),
		uintptr(unsafe.Pointer(overlapped)),
		uintptr(unsafe.Pointer(numberOfBytesTransferred)),
		uintptr(milliseconds),
		alert,
	)
	if r1 == 0 {
		return err
	}
	return nil
}

func (d *Handle) Send(
	ip []byte,
	addr *Address,
) (int, error) {

	n, err := global.send(d.handle, ip, addr)
	return n, errors.WithStack(err)
}

func (d *Handle) SendEx(
	ip []byte, flag uint64,
	addr *Address,
	ol *windows.Overlapped,
) (int, error) {

	n, err := global.sendEx(d.handle, ip, flag, addr, ol)
	return n, errors.WithStack(err)
}

func (d *Handle) Shutdown(how Shutdown) error {
	err := global.shutdown(d.handle, how)
	return errors.WithStack(err)
}

func (d *Handle) SetParam(param PARAM, value uint64) error {
	err := global.setParam(d.handle, param, value)
	return errors.WithStack(err)
}

func (d *Handle) GetParam(param PARAM) (value uint64, err error) {
	val, err := global.getParam(d.handle, param)
	return val, errors.WithStack(err)
}
