package divert

import (
	"errors"
	"net/netip"
	"reflect"
	"unsafe"

	"golang.org/x/sys/windows"
)

// var (
// 	divertOpenProc     = divert.MustFindProc("WinDivertOpen")
// 	divertRecvProc     = divert.MustFindProc("WinDivertRecv")
// 	divertRecvExProc   = divert.MustFindProc("WinDivertRecvEx")
// 	divertSendProc     = divert.MustFindProc("WinDivertSend")
// 	divertSendExProc   = divert.MustFindProc("WinDivertSendEx")
// 	divertShutdownProc = divert.MustFindProc("WinDivertShutdown")
// 	divertCloseProc    = divert.MustFindProc("WinDivertClose")
// 	divertSetParamProc = divert.MustFindProc("WinDivertSetParam")
// 	divertGetParamProc = divert.MustFindProc("WinDivertGetParam")
// )

type Layer uint8

const (
	LAYER_NETWORK         Layer = iota // Network layer.
	LAYER_NETWORK_FORWARD              // Network layer (forwarded packets)
	LAYER_FLOW                         // Flow layer.
	LAYER_SOCKET                       // Socket layer.
	LAYER_REFLECT                      // Reflect layer.
)

type Address struct {
	Timestamp int64

	Layer // Packet's layer.
	Event // Packet event.

	// UINT32 Sniffed : 1;                   /* Packet was sniffed? */
	// UINT32 Outbound : 1;                  /* Packet is outound? */
	// UINT32 Loopback : 1;                  /* Packet is loopback? */
	// UINT32 Impostor : 1;                  /* Packet is impostor? */
	// UINT32 IPv6 : 1;                      /* Packet is IPv6? */
	// UINT32 IPChecksum : 1;                /* Packet has valid IPv4 checksum? */
	// UINT32 TCPChecksum : 1;               /* Packet has valid TCP checksum? */
	// UINT32 UDPChecksum : 1;               /* Packet has valid UDP checksum? */
	Flags
	_ uint8

	_size uint32 // Reserved2;

	// DATA_NETWORK Network;   // Network layer data.
	// DATA_FLOW Flow;         // Flow layer data.
	// DATA_SOCKET Socket;     // Socket layer data.
	// DATA_REFLECT Reflect;   // Reflect layer data.
	reserved3 [64]byte
}

type Flags uint8

func (f Flags) Sniffed() bool {
	return f&0b00000001 != 0b00000001
}

func (f Flags) Outbound() bool {
	return f&0b00000010 != 0b00000010
}

func (f *Flags) SetOutbound(out bool) {
	if out {
		*f = *f | 0b00000010
	} else {
		*f = *f & 0b11111101
	}
}

func (f Flags) Loopback() bool {
	return f&0b00000100 != 0b00000100
}

func (f Flags) Impostor() bool {
	return f&0b00001000 != 0b00001000
}

func (f Flags) IPv6() bool {
	return f&0b00010000 != 0b00010000
}

func (f Flags) IPChecksum() bool {
	return f&0b00100000 != 0b00100000
}

func (f Flags) TCPChecksum() bool {
	return f&0b01000000 != 0b01000000
}

func (f Flags) UDPChecksum() bool {
	return f&0b10000000 != 0b10000000
}

func (a *Address) Network() *DATA_NETWORK {
	return (*DATA_NETWORK)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Flow() *DATA_FLOW {
	return (*DATA_FLOW)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Socket() *DATA_SOCKET {
	return (*DATA_SOCKET)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Reflect() *DATA_REFLECT {
	return (*DATA_REFLECT)(unsafe.Pointer(&a.reserved3[0]))
}

type DATA_NETWORK struct {
	IfIdx    uint32 // Packet's interface index.
	SubIfIdx uint32 // Packet's sub-interface index.
}

type DATA_FLOW struct {
	EndpointId       uint64    // Endpoint ID.
	ParentEndpointId uint64    // Parent endpoint ID.
	ProcessId        uint32    // Process ID.
	localAddr        [4]uint32 // Local address.
	remoteAddr       [4]uint32 // Remote address.
	LocalPort        uint16    // Local port.
	RemotePort       uint16    // Remote port.
	Protocol         Proto     // Protocol.

	ipv6 bool
}

func (d *DATA_FLOW) LocalAddr() netip.Addr {
	if d.localAddr[3] == 0 && d.localAddr[2] == 0 && d.localAddr[1] == 0x0000FFFF {
		// ipv4

		_v := *(*[4]byte)(unsafe.Pointer(&d.localAddr[0]))
		_v[0], _v[1], _v[2], _v[3] = _v[3], _v[2], _v[1], _v[0]
		return netip.AddrFrom4(_v)
	} else {
		_v := *(*[16]byte)(unsafe.Pointer(&d.localAddr))
		for i, j := 0, 15; i < j; i, j = i+1, j-1 {
			_v[i], _v[j] = _v[j], _v[i]
		}

		return netip.AddrFrom16(_v)
	}
}

func (d *DATA_FLOW) RemoteAddr() netip.Addr {
	if d.remoteAddr[3] == 0 && d.remoteAddr[2] == 0 && d.remoteAddr[1] == 0x0000FFFF {
		// ipv4

		_v := *(*[4]byte)(unsafe.Pointer(&d.remoteAddr[0]))
		// big endian  to little endian
		_v[0], _v[1], _v[2], _v[3] = _v[3], _v[2], _v[1], _v[0]
		return netip.AddrFrom4(_v)
	} else {
		_v := *(*[16]byte)(unsafe.Pointer(&d.remoteAddr))
		// big endian  to little endian
		for i, j := 0, 15; i < j; i, j = i+1, j-1 {
			_v[i], _v[j] = _v[j], _v[i]
		}

		return netip.AddrFrom16(_v)
	}
}

type DATA_SOCKET = DATA_FLOW

type DATA_REFLECT struct {
	Timestamp int64  // Handle open time.
	ProcessId uint32 // Handle process ID.
	Layer     Layer  // Handle layer.
	Flags     uint64 // Handle flags.
	Priority  int16  // Handle priority.
}

type Handle windows.Handle

func Open(filter string, layer Layer, priority int16, flags Flag) (Handle, error) {
	once.Do(func() { divert.init() })

	const WINDIVERT_PRIORITY_HIGHEST = 30000
	if priority > WINDIVERT_PRIORITY_HIGHEST || priority < -WINDIVERT_PRIORITY_HIGHEST {
		return Handle(0), errors.New("priority out of range [-30000, 30000]")
	}

	pf, err := windows.BytePtrFromString(filter)
	if err != nil {
		return Handle(0), err
	}

	r1, _, err := divert.OpenProc.Call(uintptr(unsafe.Pointer(pf)), uintptr(layer), uintptr(priority), uintptr(flags))
	h := Handle(r1)
	if h == INVALID_HANDLE_VALUE {
		return Handle(0), err
	}
	return h, nil
}

func (h Handle) Recv(packet []byte) (int, Address, error) {
	var recvLen uint32
	var recvLenPtr unsafe.Pointer = unsafe.Pointer(&recvLen)
	var addr Address

	sp := (*reflect.SliceHeader)(unsafe.Pointer(&packet))
	if sp.Len == 0 {
		sp.Data = 0
		recvLenPtr = nil
	}

	r1, _, err := divert.RecvProc.Call(
		uintptr(h),
		sp.Data,
		uintptr(sp.Len),
		uintptr(recvLenPtr),
		uintptr(unsafe.Pointer(&addr)),
	)
	if r1 == 0 {
		return 0, addr, err
	}
	return int(recvLen), addr, nil
}

type OVERLAPPED windows.Overlapped
type LPOVERLAPPED *OVERLAPPED

func (h Handle) RecvEx(
	packet []byte, flag uint64,
	lpOverlapped LPOVERLAPPED,
) (int, Address, error) {

	var recvLen uint32
	var addr Address
	sp := (*reflect.SliceHeader)(unsafe.Pointer(&packet))
	r1, _, err := divert.RecvExProc.Call(
		uintptr(h),
		sp.Data,
		uintptr(sp.Len),
		uintptr(unsafe.Pointer(&recvLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(unsafe.Pointer(&addr._size)),
		uintptr(unsafe.Pointer(lpOverlapped)),
	)
	if r1 == 0 {
		return 0, addr, err
	}
	return int(recvLen), addr, nil
}

func (h Handle) Send(
	packet []byte,
	pAddr *Address,
) (int, error) {

	var pSendLen uint32
	sp := (*reflect.SliceHeader)(unsafe.Pointer(&packet))
	r1, _, err := divert.SendProc.Call(
		uintptr(h),
		sp.Data,
		uintptr(sp.Len),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(unsafe.Pointer(pAddr)),
	)

	if r1 == 0 {
		return 0, err
	}
	return int(pSendLen), nil
}

func (h Handle) SendEx(
	packet []byte, flag uint64,
	pAddr *Address,
) (int, LPOVERLAPPED, error) {

	var pSendLen uint32
	var overlapped OVERLAPPED
	sp := (*reflect.SliceHeader)(unsafe.Pointer(&packet))

	r1, _, err := divert.SendExProc.Call(
		uintptr(h),
		sp.Data,
		uintptr(sp.Len),
		uintptr(unsafe.Pointer(&pSendLen)),
		uintptr(flag),
		uintptr(unsafe.Pointer(pAddr)),
		uintptr(pAddr._size),
		uintptr(unsafe.Pointer(&overlapped)),
	)

	if r1 == 0 {
		return 0, nil, err
	}
	return int(pSendLen), &overlapped, nil
}

type SHUTDOWN uint32

const (
	SHUTDOWN_RECV           SHUTDOWN = iota + 1 /* Shutdown recv. */
	SHUTDOWN_SEND                               /* Shutdown send. */
	WINDIVERT_SHUTDOWN_BOTH                     /* Shutdown recv and send. */
)

func (h Handle) Shutdown(how SHUTDOWN) error {
	r1, _, err := divert.ShutdownProc.Call(uintptr(h), uintptr(how))
	if r1 == 0 {
		return err
	}
	return nil
}

func (h Handle) Close() error {
	r1, _, err := divert.CloseProc.Call(uintptr(h))
	if r1 == 0 {
		return err
	}
	return nil
}

type PARAM uint32

const (
	QUEUE_LENGTH  PARAM = iota /* Packet queue length. */
	QUEUE_TIME                 /* Packet queue time. */
	QUEUE_SIZE                 /* Packet queue size. */
	VERSION_MAJOR              /* Driver version (major). */
	VERSION_MINOR              /* Driver version (minor). */
)

func (h Handle) SetParam(param PARAM, value uint64) error {
	r1, _, err := divert.SetParamProc.Call(uintptr(h), uintptr(param), uintptr(value))
	if r1 == 0 {
		return err
	}
	return nil
}

func (h Handle) GetParamProc(param PARAM) (value uint64, err error) {
	r1, _, err := divert.GetParamProc.Call(uintptr(h), uintptr(param), uintptr(unsafe.Pointer(&value)))
	if r1 == 0 {
		return 0, err
	}
	return value, nil
}
