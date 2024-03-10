//go:build windows
// +build windows

package divert

import (
	"context"
	"fmt"
	"syscall"

	"golang.org/x/sys/windows"
)

type Handle struct {
	handle uintptr
}

func (d *Handle) Close() error {
	err := global.close(d.handle)
	return err
}

// Recv receive (read) a ip packet from a WinDivert handle.
func (d *Handle) Recv(ip []byte, addr *Address) (int, error) {
	n, err := global.recv(d.handle, ip, addr)
	return n, err
}

// RecvEx receive (read) a ip packet from a WinDivert handle.
func (d *Handle) RecvEx(ip []byte, addr *Address, ol *windows.Overlapped) error {
	err := global.recvEx(d.handle, ip, addr, ol)
	return err
}

func (d *Handle) RecvCtx(ctx context.Context, ip []byte, addr *Address) (n int, err error) {
	var ol = &windows.Overlapped{}
	ol.HEvent, err = windows.CreateEvent(nil, 0, 0, nil)
	if err != nil {
		return 0, err
	}
	defer windows.CloseHandle(ol.HEvent)

	err = d.RecvEx(ip, addr, ol)
	if err != nil && err != syscall.ERROR_IO_PENDING {
		return 0, err
	}

	for {
		e, err := windows.WaitForSingleObject(ol.HEvent, 100)
		if err != nil {
			return 0, err
		}
		switch e {
		case windows.WAIT_OBJECT_0:
			var m uint32
			err = windows.GetOverlappedResult(windows.Handle(d.handle), ol, &m, true)
			if err != nil {
				return 0, err
			}
			return int(m), nil
		case uint32(windows.WAIT_TIMEOUT):
			select {
			case <-ctx.Done():
				err = windows.CancelIoEx(windows.Handle(d.handle), ol)
				if err != nil {
					return 0, err
				}
				e, err := windows.WaitForSingleObject(ol.HEvent, 0)
				if e == windows.WAIT_OBJECT_0 {
					return 0, ctx.Err()
				} else {
					return 0, err
				}
			default:
			}
		default:
			return 0, fmt.Errorf("invalid WaitForSingleObject result %d", e)
		}
	}

}

func (d *Handle) Send(
	ip []byte,
	addr *Address,
) (int, error) {

	n, err := global.send(d.handle, ip, addr)
	return n, err
}

// SendEx send (write/inject) a packet to a WinDivert handle.
func (d *Handle) SendEx(
	ip []byte, flag uint64,
	addr *Address,
	ol *windows.Overlapped,
) (int, error) {

	n, err := global.sendEx(d.handle, ip, flag, addr, ol)
	return n, err
}

func (d *Handle) Shutdown(how SHUTDOWN) error {
	err := global.shutdown(d.handle, how)
	return err
}

func (d *Handle) SetParam(param PARAM, value uint64) error {
	err := global.setParam(d.handle, param, value)
	return err
}

func (d *Handle) GetParam(param PARAM) (value uint64, err error) {
	val, err := global.getParam(d.handle, param)
	return val, err
}
