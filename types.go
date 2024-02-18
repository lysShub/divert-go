package divert

import (
	"net/netip"
	"unsafe"
)

type Layer uint8

const (
	NETWORK         Layer = iota // Network layer.
	NETWORK_FORWARD              // Network layer (forwarded packets)
	FLOW                         // Flow layer.
	SOCKET                       // Socket layer.
	REFLECT                      // Reflect layer.
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

	reserved1 uint8
	reserved2 uint32

	// DATA_NETWORK Network;   // Network layer data.
	// DATA_FLOW Flow;         // Flow layer data.
	// DATA_SOCKET Socket;     // Socket layer data.
	// DATA_REFLECT Reflect;   // Reflect layer data.
	reserved3 [64]byte
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

type Flags uint8

func (f Flags) Sniffed() bool {
	return f&0b00000001 == 0b00000001
}

func (f Flags) Outbound() bool {
	return f&0b00000010 == 0b00000010
}

func (f *Flags) SetOutbound(out bool) {
	if out {
		*f = *f | 0b00000010
	} else {
		*f = *f & 0b11111101
	}
}

func (f Flags) Loopback() bool {
	return f&0b00000100 == 0b00000100
}

func (f *Flags) SetLoopback(loop bool) {
	if loop {
		*f = *f | 0b00000100
	} else {
		*f = *f & 0b11111011
	}
}

func (f Flags) Impostor() bool {
	return f&0b00001000 == 0b00001000
}

func (f *Flags) SetImpostor(impostor bool) {
	if impostor {
		*f = *f | 0b00001000
	} else {
		*f = *f & 0b11110111
	}
}

func (f Flags) IPv6() bool {
	return f&0b00010000 == 0b00010000
}

func (f *Flags) SetIPv6(ipv6 bool) {
	if ipv6 {
		*f = *f | 0b00010000
	} else {
		*f = *f & 0b11101111
	}
}

func (f Flags) IPChecksum() bool {
	return f&0b00100000 == 0b00100000
}

func (f *Flags) SetIPChecksum(sum bool) {
	if sum {
		*f = *f | 0b00100000
	} else {
		*f = *f & 0b11011111
	}
}

func (f Flags) TCPChecksum() bool {
	return f&0b01000000 == 0b01000000
}

func (f *Flags) SetTCPChecksum(sum bool) {
	if sum {
		*f = *f | 0b01000000
	} else {
		*f = *f & 0b10111111
	}
}

func (f Flags) UDPChecksum() bool {
	return f&0b10000000 == 0b10000000
}

func (f *Flags) SetUDPChecksum(sum bool) {
	if sum {
		*f = *f | 0b10000000
	} else {
		*f = *f & 0b01111111
	}
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
}

func (d *DATA_FLOW) LocalAddr() netip.Addr {
	if d.localAddr[3] == 0 && d.localAddr[2] == 0 && d.localAddr[1] == 0xFFFF {
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
	if d.remoteAddr[3] == 0 && d.remoteAddr[2] == 0 && d.remoteAddr[1] == 0xFFFF {
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

type PARAM uint32

const (
	QUEUE_LENGTH  PARAM = iota /* Packet queue length. */
	QUEUE_TIME                 /* Packet queue time. */
	QUEUE_SIZE                 /* Packet queue size. */
	VERSION_MAJOR              /* Driver version (major). */
	VERSION_MINOR              /* Driver version (minor). */
)

type SHUTDOWN uint32

const (
	RECV SHUTDOWN = iota + 1 /* Shutdown recv. */
	SEND                     /* Shutdown send. */
	BOTH                     /* Shutdown recv and send. */
)

const PRIORITY_HIGHEST = 30000
