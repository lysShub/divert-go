//go:build windows
// +build windows

package divert

import (
	"os"
	"sync"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

var global divert

func MustLoad[T string | MemMode](p T) struct{} {
	err := Load(p)
	if err != nil {
		panic(err)
	}
	return struct{}{}
}

func Load[T string | MemMode](p T) error {
	global.Lock()
	defer global.Unlock()
	if global.dll != nil {
		return ErrLoaded{}
	}

	var err error
	switch p := any(p).(type) {
	case string:
		global.dll, err = loadFileDLL(p)
		if err != nil {
			return errors.WithStack(err)
		}
	case MemMode:
		if err = driverInstall(p.Sys); err != nil {
			return errors.WithStack(err)
		}

		global.dll, err = loadMemDLL(p.DLL)
		if err != nil {
			return err
		}
	default:
		return windows.ERROR_INVALID_PARAMETER
	}

	err = global.init()
	return errors.WithStack(err)
}

type ErrLoaded struct{}

func (e ErrLoaded) Error() string {
	return "divert loaded"
}

func Release() error {
	global.Lock()
	defer global.Unlock()
	if global.dll == nil {
		return nil
	}

	err := global.dll.Release()
	global.dll = nil
	return errors.WithStack(err)
}

type divert struct {
	sync.RWMutex

	dll dll

	procOpen                uintptr // WinDivertOpen
	procHelperCompileFilter uintptr // WinDivertHelperCompileFilter
	procHelperEvalFilter    uintptr // WinDivertHelperEvalFilter
	procHelperFormatFilter  uintptr // WinDivertHelperFormatFilter

	procRecv     uintptr // WinDivertRecv
	procRecvEx   uintptr // WinDivertRecvEx
	procSend     uintptr // WinDivertSend
	procSendEx   uintptr // WinDivertSendEx
	procShutdown uintptr // WinDivertShutdown
	procClose    uintptr // WinDivertClose
	procSetParam uintptr // WinDivertSetParam
	procGetParam uintptr // WinDivertGetParam
}

func (d *divert) init() (err error) {
	if d.procOpen, err = d.dll.FindProc("WinDivertOpen"); err != nil {
		goto ret
	}
	if d.procHelperCompileFilter, err = d.dll.FindProc("WinDivertHelperCompileFilter"); err != nil {
		goto ret
	}
	if d.procHelperEvalFilter, err = d.dll.FindProc("WinDivertHelperEvalFilter"); err != nil {
		goto ret
	}
	if d.procHelperFormatFilter, err = d.dll.FindProc("WinDivertHelperFormatFilter"); err != nil {
		goto ret
	}

	if d.procRecv, err = d.dll.FindProc("WinDivertRecv"); err != nil {
		goto ret
	}
	if d.procRecvEx, err = d.dll.FindProc("WinDivertRecvEx"); err != nil {
		goto ret
	}
	if d.procSend, err = d.dll.FindProc("WinDivertSend"); err != nil {
		goto ret
	}
	if d.procSendEx, err = d.dll.FindProc("WinDivertSendEx"); err != nil {
		goto ret
	}
	if d.procShutdown, err = d.dll.FindProc("WinDivertShutdown"); err != nil {
		goto ret
	}
	if d.procClose, err = d.dll.FindProc("WinDivertClose"); err != nil {
		goto ret
	}
	if d.procSetParam, err = d.dll.FindProc("WinDivertSetParam"); err != nil {
		goto ret
	}
	if d.procGetParam, err = d.dll.FindProc("WinDivertGetParam"); err != nil {
		goto ret
	}

ret:
	if err != nil {
		d.dll.Release()
		d.dll = nil
	}
	return err
}

func (d *divert) calln(trap uintptr, args ...uintptr) (r1, r2 uintptr, err error) {
	d.RLock()
	defer d.RUnlock()

	if d.dll == nil {
		return 0, 0, os.ErrClosed
	}

	var e syscall.Errno
	r1, r2, e = syscall.SyscallN(trap, args...)
	switch e {
	case windows.ERROR_INVALID_HANDLE,
		windows.ERROR_OPERATION_ABORTED,
		windows.ERROR_NO_DATA:

		err = os.ErrClosed
	default:
		err = e
	}
	return r1, r2, err
}

func (d *divert) open(filter string, layer Layer, priority int16, flags Flag) (uintptr, error) {
	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return 0, err
	}
	if _, ok := d.dll.(*mem); ok {
		flags = flags | NoInstall
	}

	r1, _, e := d.calln(
		d.procOpen,
		uintptr(unsafe.Pointer(pf)),
		uintptr(layer),
		uintptr(priority),
		uintptr(flags),
	)
	if r1 == 0 {
		return 0, e
	}
	return r1, nil
}
func (d *divert) helperCompileFilter(filter string, layer Layer) (string, error) {
	var buf = make([]byte, len(filter)+64)
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}

	r1, _, e := d.calln(
		d.procHelperCompileFilter,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		0,
		0,
	)
	if r1 == 0 {
		return "", e
	}
	for i, v := range buf {
		if v == 0 {
			return string(buf[:i]), nil
		}
	}
	return "", nil
}
func (d *divert) helperEvalFilter(filter string, ip []byte, addr *Address) (bool, error) {
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}

	r1, _, e := d.calln(
		d.procHelperEvalFilter,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(unsafe.Pointer(&ip[0])),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return false, e
	}
	return true, nil
}
func (d *divert) helperFormatFilter(filter string, layer Layer) (string, error) {
	var buf = make([]uint8, len(filter)+64)
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}

	r1, _, e := d.calln(
		d.procHelperFormatFilter,
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", e
	}

	for i, v := range buf {
		if v == 0 {
			buf = buf[0:i]
			break
		}
	}
	return string(buf), nil
}

func (d *divert) recv(handle uintptr, ip []byte, addr *Address) (int, error) {
	var recvLen uint32
	var dataPtr, recvLenPtr uintptr
	if len(ip) > 0 {
		dataPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
		recvLenPtr = uintptr(unsafe.Pointer(&recvLen))
	}

	r1, _, err := d.calln(
		d.procRecv,
		handle,
		dataPtr,
		uintptr(len(ip)),
		recvLenPtr,
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, err
	}
	return int(recvLen), nil
}
func (d *divert) recvEx(handle uintptr, ip []byte, addr *Address, ol *windows.Overlapped) error {
	var ipPtr uintptr
	if len(ip) > 0 {
		ipPtr = uintptr(unsafe.Pointer(unsafe.SliceData(ip)))
	}

	r1, _, err := d.calln(
		d.procRecvEx,
		handle,
		ipPtr,                         // pPacket
		uintptr(len(ip)),              // packetLen
		0,                             // pRecvLen  NOTICE: not work
		uintptr(0),                    // flags 0
		uintptr(unsafe.Pointer(addr)), // pAddr
		0,                             // pAddrLen
		uintptr(unsafe.Pointer(ol)),   // lpOverlapped
	)
	if r1 == 0 {
		return err
	}
	return nil
}
func (d *divert) send(handle uintptr, ip []byte, addr *Address) (int, error) {
	var sendLen uint32

	r1, _, err := d.calln(
		d.procSend,
		handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return 0, err
	}
	return int(sendLen), nil
}
func (d *divert) sendEx(handle uintptr, ip []byte, flag uint64, addr *Address, ol *windows.Overlapped) (int, error) {
	var sendLen uint32

	// todo: support batch
	r1, _, err := d.calln(
		d.procSendEx,
		handle,
		uintptr(unsafe.Pointer(unsafe.SliceData(ip))),
		uintptr(len(ip)),
		uintptr(unsafe.Pointer(&sendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(addr)),
		0,
		uintptr(unsafe.Pointer(ol)),
	)
	if r1 == 0 {
		return 0, err
	}
	return int(sendLen), nil
}
func (d *divert) shutdown(handle uintptr, how Shutdown) error {

	r1, _, err := d.calln(
		d.procShutdown,
		handle,
		uintptr(how),
	)
	if r1 == 0 {
		return err
	}
	return nil
}
func (d *divert) close(handle uintptr) error {
	r1, _, err := d.calln(d.procClose, handle)
	if r1 == 0 {
		return err
	}
	return nil
}
func (d *divert) setParam(handle uintptr, param PARAM, value uint64) error {

	r1, _, err := d.calln(
		d.procSetParam,
		handle,
		uintptr(param),
		uintptr(value),
	)
	if r1 == 0 {
		return err
	}
	return nil
}
func (d *divert) getParam(handle uintptr, param PARAM) (value uint64, err error) {

	r1, _, e := d.calln(
		d.procGetParam,
		handle,
		uintptr(param),
		uintptr(unsafe.Pointer(&value)),
	)
	if r1 == 0 {
		return 0, e
	}
	return value, nil
}

func Open(filter string, layer Layer, priority int16, flags Flag) (*Handle, error) {
	fd, err := global.open(filter, layer, priority, flags)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return &Handle{
		handle: fd,
		layer:  layer,
	}, nil
}

func HelperCompileFilter(filter string, layer Layer) (string, error) {
	str, err := global.helperCompileFilter(filter, layer)
	return str, errors.WithStack(err)
}

func HelperEvalFilter(filter string, ip []byte, addr *Address) (bool, error) {
	ok, err := global.helperEvalFilter(filter, ip, addr)
	return ok, errors.WithStack(err)
}

func HelperFormatFilter(filter string, layer Layer) (string, error) {
	str, err := global.helperFormatFilter(filter, layer)
	return str, errors.WithStack(err)
}
