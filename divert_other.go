//go:build !windows
// +build !windows

package divert

import "errors"

type Handle uintptr

var errNotImplemented = errors.New("not implemented")

func Open(filter string, layer Layer, priority int16, flags Flag) (hdl Handle, err error) {
	return INVALID_HANDLE_VALUE, errNotImplemented
}

func (h Handle) Recv(packet []byte) (int, Address, error) { return 0, Address{}, errNotImplemented }

type OVERLAPPED struct{}
type LPOVERLAPPED *OVERLAPPED

func (h Handle) RecvEx(packet []byte, flag uint64, lpOverlapped LPOVERLAPPED) (int, Address, error) {
	return 0, Address{}, errNotImplemented
}

func (h Handle) Send(packet []byte, pAddr *Address) (int, error) { return 0, errNotImplemented }

func (h Handle) SendEx(packet []byte, flag uint64, pAddr *Address) (int, LPOVERLAPPED, error) {
	return 0, nil, errNotImplemented
}

func (h Handle) Shutdown(how SHUTDOWN) error { return errNotImplemented }

func (h Handle) Close() error { return errNotImplemented }

func (h Handle) SetParam(param PARAM, value uint64) error { return errNotImplemented }

func (h Handle) GetParamProc(param PARAM) (value uint64, err error) { return 0, errNotImplemented }

func HelperCompileFilter(filter string, layer Layer) (string, error) { return "", errNotImplemented }

func HelperEvalFilter(filter string, packet []byte, addr *Address) (bool, error) {
	return false, errNotImplemented
}

func HelperFormatFilter(filter string, layer Layer) (string, error) { return "", errNotImplemented }
