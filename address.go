package divert

import (
	"encoding/binary"
	"net/netip"
	"unsafe"
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

func (a *Address) Network() *DateNetwork {
	return (*DateNetwork)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Flow() *DataFlow {
	return (*DataFlow)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Socket() *DataSocket {
	return (*DataSocket)(unsafe.Pointer(&a.reserved3[0]))
}
func (a *Address) Reflect() *DataReflect {
	return (*DataReflect)(unsafe.Pointer(&a.reserved3[0]))
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

type DateNetwork struct {
	IfIdx    uint32 // Packet's interface index.
	SubIfIdx uint32 // Packet's sub-interface index.
}

type DataFlow struct {
	EndpointId       uint64    // Endpoint ID.
	ParentEndpointId uint64    // Parent endpoint ID.
	ProcessId        uint32    // Process ID.
	localAddr        [4]uint32 // Local address.
	remoteAddr       [4]uint32 // Remote address.
	LocalPort        uint16    // Local port.
	RemotePort       uint16    // Remote port.
	Protocol         Proto     // Protocol.
}

func (d *DataFlow) LocalAddr() netip.Addr {
	var ip = make([]byte, 0, 16)
	for i := 3; i >= 0; i-- {
		ip = binary.BigEndian.AppendUint32(ip, d.localAddr[i])
	}

	addr := netip.AddrFrom16([16]byte(ip))
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	return addr
}

func (d *DataFlow) RemoteAddr() netip.Addr {
	var ip = make([]byte, 0, 16)
	for i := 3; i >= 0; i-- {
		ip = binary.BigEndian.AppendUint32(ip, d.remoteAddr[i])
	}

	addr := netip.AddrFrom16([16]byte(ip))
	if addr.Is4In6() {
		addr = netip.AddrFrom4(addr.As4())
	}
	return addr
}

type DataSocket = DataFlow

type DataReflect struct {
	Timestamp int64  // Handle open time.
	ProcessId uint32 // Handle process ID.
	Layer     Layer  // Handle layer.
	Flags     uint64 // Handle flags.
	Priority  int16  // Handle priority.
}
