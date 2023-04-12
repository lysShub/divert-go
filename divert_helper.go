package divert

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	winDivertHelperParsePacketProc       = divert.MustFindProc("WinDivertHelperParsePacket")
	winDivertHelperHashPacketProc        = divert.MustFindProc("WinDivertHelperHashPacket")
	winDivertHelperParseIPv4AddressProc  = divert.MustFindProc("WinDivertHelperParseIPv4Address")
	winDivertHelperParseIPv6AddressProc  = divert.MustFindProc("WinDivertHelperParseIPv6Address")
	winDivertHelperFormatIPv4AddressProc = divert.MustFindProc("WinDivertHelperFormatIPv4Address")
	winDivertHelperFormatIPv6AddressProc = divert.MustFindProc("WinDivertHelperFormatIPv6Address")
	winDivertHelperCalcChecksumsProc     = divert.MustFindProc("WinDivertHelperCalcChecksums")
	winDivertHelperDecrementTTLProc      = divert.MustFindProc("WinDivertHelperDecrementTTL")
	winDivertHelperCompileFilterProc     = divert.MustFindProc("WinDivertHelperCompileFilter")
	winDivertHelperEvalFilterProc        = divert.MustFindProc("WinDivertHelperEvalFilter")
	winDivertHelperFormatFilterProc      = divert.MustFindProc("WinDivertHelperFormatFilter")
	winDivertHelperNtohIPv6AddressProc   = divert.MustFindProc("WinDivertHelperNtohIPv6Address")
	winDivertHelperNtohIpv6AddressProc   = divert.MustFindProc("WinDivertHelperNtohIPv6Address")
	winDivertHelperNtohlProc             = divert.MustFindProc("WinDivertHelperNtohl")
	winDivertHelperNtohllProc            = divert.MustFindProc("WinDivertHelperNtohll")
	winDivertHelperNtohsProc             = divert.MustFindProc("WinDivertHelperNtohs")
	winDivertHelperHtonIPv6AddressProc   = divert.MustFindProc("WinDivertHelperHtonIPv6Address")
	winDivertHelperHtonIpv6AddressProc   = divert.MustFindProc("WinDivertHelperHtonIPv6Address")
	winDivertHelperHtonlProc             = divert.MustFindProc("WinDivertHelperHtonl")
	winDivertHelperHtonllProc            = divert.MustFindProc("WinDivertHelperHtonll")
	winDivertHelperHtonsProc             = divert.MustFindProc("WinDivertHelperHtons")
)

type IPHDR struct {
	// UINT8  HdrLength : 4;
	// UINT8  Version : 4;
	HdrLengthVersion uint8

	TOS      uint8
	Length   uint16
	Id       uint16
	FragOff0 uint16
	TTL      uint8
	Protocol uint8
	Checksum uint16
	SrcAddr  uint32
	DstAddr  uint32
}

func (w *IPHDR) HdrLength() uint8 {
	return uint8(w.HdrLengthVersion & 0b1111)
}
func (w *IPHDR) Version() uint8 {
	return uint8((w.HdrLengthVersion >> 4) & 0b1111)
}

type IPV6HDR struct {
	// UINT8  TrafficClass0 : 4;
	// UINT8  Version : 4;
	TrafficClass0Version uint8

	// UINT8  FlowLabel0 : 4;
	// UINT8  TrafficClass1 : 4;
	FlowLabel0TrafficClass1 uint8

	FlowLabel1 uint16
	Length     uint16
	NextHdr    uint8
	HopLimit   uint8
	SrcAddr    [4]uint32
	UINT32     [4]uint32
}

func (w *IPV6HDR) TrafficClass0() uint8 {
	return uint8(w.TrafficClass0Version & 0b1111)
}

func (w *IPV6HDR) Version() uint8 {
	return uint8((w.TrafficClass0Version >> 4) & 0b1111)
}

func (w *IPV6HDR) TrafficClass1() uint8 {
	return uint8((w.FlowLabel0TrafficClass1 >> 4) & 0b1111)
}

func (w *IPV6HDR) FlowLabel0() uint8 {
	return uint8(w.FlowLabel0TrafficClass1 & 0b1111)
}

type ICMPHDR struct {
	Type     uint8
	Code     uint8
	Checksum uint16
	Body     uint32
}

type ICMPV6HDR ICMPHDR

type TCPHDR struct {
	SrcPort uint16
	DstPort uint16
	SeqNum  uint32
	AckNum  uint32

	// UINT16 Reserved1 : 4;
	// UINT16 HdrLength : 4;
	Reserved1HdrLength uint8
	// UINT16 Fin : 1;
	// UINT16 Syn : 1;
	// UINT16 Rst : 1;
	// UINT16 Psh : 1;
	// UINT16 Ack : 1;
	// UINT16 Urg : 1;
	// UINT16 Reserved2 : 2;
	Flag uint8

	Window   uint16
	Checksum uint16
	UrgPtr   uint16
}

func (w *TCPHDR) HdrLength() uint8 {
	return uint8((w.Reserved1HdrLength >> 4) & 0b1111)
}

func (w *TCPHDR) Fin() bool {
	return (w.Flag & 0b1) == 0b1
}

func (w *TCPHDR) Syn() bool {
	return (w.Flag & 0b10) == 0b10
}

func (w *TCPHDR) Rst() bool {
	return (w.Flag & 0b100) == 0b100
}

func (w *TCPHDR) Psh() bool {
	return (w.Flag & 0b1000) == 0b1000
}

func (w *TCPHDR) Ack() bool {
	return (w.Flag & 0b10000) == 0b10000
}

func (w *TCPHDR) Urg() bool {
	return (w.Flag & 0b100000) == 0b100000
}

type UDPHDR struct {
	SrcPort  uint16
	DstPort  uint16
	Length   uint16
	Checksum uint16
}

func WinDivertHelperParsePacket(packet []byte) (
	pIpHdr *IPHDR,
	pIpv6Hdr *IPV6HDR,
	Protocol uint8,
	pIcmpHdr *ICMPHDR,
	pIcmpv6Hdr *ICMPV6HDR,
	pTcpHdr *TCPHDR,
	pUdpHdr *UDPHDR,
	Data []byte,
	Next []byte,
	err error,
) {

	// init
	{
		pIpHdr = &IPHDR{}
		pIpv6Hdr = &IPV6HDR{}
		pIcmpHdr = &ICMPHDR{}
		pIcmpv6Hdr = &ICMPV6HDR{}
		pTcpHdr = &TCPHDR{}
		pUdpHdr = &UDPHDR{}
		Data = make([]byte, len(packet))
		Next = make([]byte, len(packet))
	}

	var DataLen uint32
	var NextLen uint32
	defer func() {
		Data = Data[:DataLen]
		Next = Next[:NextLen]
	}()
	r1, _, err := winDivertHelperParsePacketProc.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&pIpHdr)),
		uintptr(unsafe.Pointer(&pIpv6Hdr)),
		uintptr(unsafe.Pointer(&Protocol)),
		uintptr(unsafe.Pointer(&pIcmpHdr)),
		uintptr(unsafe.Pointer(&pIcmpv6Hdr)),
		uintptr(unsafe.Pointer(&pTcpHdr)),
		uintptr(unsafe.Pointer(&pUdpHdr)),
		uintptr(unsafe.Pointer(&Data[0])),
		uintptr(unsafe.Pointer(&DataLen)),
		uintptr(unsafe.Pointer(&Next[0])),
		uintptr(unsafe.Pointer(&NextLen)),
	)

	if r1 == 0 {
		return nil, nil, 0, nil, nil, nil, nil, nil, nil, err
	}
	return
}

func WinDivertHelperHashPacket(packet []byte, seed uint64) (uint64, error) {
	r1, _, err := winDivertHelperHashPacketProc.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(seed),
	)
	if r1 == 0 {
		return 0, err
	}
	return uint64(r1), nil
}

func WinDivertHelperParseIPv4Address(addrStr string) (uint32, error) {
	var ip4 uint32

	pAddrStr, err := syscall.UTF16PtrFromString(addrStr)
	if err != nil {
		return 0, err
	}
	r1, _, err := winDivertHelperParseIPv4AddressProc.Call(
		uintptr(unsafe.Pointer(pAddrStr)),
		uintptr(unsafe.Pointer(&ip4)),
	)
	if r1 == 0 {
		return 0, err
	}
	return ip4, nil
}

// Deprecated: un-understandable
func WinDivertHelperParseIPv6Address(addrStr string) (uint32, error) {
	var ip6 [4]uint32

	pAddrStr, err := windows.UTF16PtrFromString(addrStr)
	if err != nil {
		return 0, err
	}
	r1, _, err := winDivertHelperParseIPv6AddressProc.Call(
		uintptr(unsafe.Pointer(pAddrStr)),
		uintptr(unsafe.Pointer(&ip6[0])),
	)
	if r1 == 0 {
		return 0, err
	}
	return ip6[0], nil
}

// Deprecated: un-understandable
func WinDivertHelperFormatIPv4Address(addr uint32) (string, error) {
	var buf [16]uint16

	r1, _, err := winDivertHelperFormatIPv4AddressProc.Call(
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:]), nil
}

// Deprecated: un-understandable
func WinDivertHelperFormatIPv6Address(addr uint32) (string, error) {
	var buf [64]uint16

	r1, _, err := winDivertHelperFormatIPv6AddressProc.Call(
		uintptr(addr),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", err
	}
	return syscall.UTF16ToString(buf[:]), nil
}

func WinDivertHelperCalcChecksums(packet []byte, flags uint64) (*Address, error) {
	var addr Address
	r1, _, err := winDivertHelperCalcChecksumsProc.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(&addr)),
		uintptr(flags),
	)
	if r1 == 0 {
		return nil, err
	}
	return &addr, nil
}

func WinDivertHelperDecrementTTL(packet []byte) bool {
	r1, _, _ := winDivertHelperDecrementTTLProc.Call(
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
	)

	return r1 != 0
}

// Deprecated: un-understandable
func WinDivertHelperCompileFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8
	var pErrorStr *uint8
	var errorPos uint32

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := winDivertHelperCompileFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
		uintptr(unsafe.Pointer(&pErrorStr)),
		uintptr(unsafe.Pointer(&errorPos)),
	)
	if r1 == 0 {
		return "", err
	}
	return string(buf[:]), nil
}

func WinDivertHelperEvalFilter(filter string, packet []byte, addr *Address) (bool, error) {
	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return false, err
	}
	r1, _, err := winDivertHelperEvalFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(unsafe.Pointer(&packet[0])),
		uintptr(len(packet)),
		uintptr(unsafe.Pointer(addr)),
	)
	if r1 == 0 {
		return false, err
	}
	return true, nil
}

func WinDivertHelperFormatFilter(filter string, layer Layer) (string, error) {
	var buf [1024]uint8

	pFilter, err := syscall.BytePtrFromString(filter)
	if err != nil {
		return "", err
	}
	r1, _, err := winDivertHelperFormatFilterProc.Call(
		uintptr(unsafe.Pointer(pFilter)),
		uintptr(layer),
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if r1 == 0 {
		return "", err
	}
	return string(buf[:]), nil
}

// Deprecated: un-understandable
func WinDivertHelperNtohIPv6Address(inAddr, outAddr []uint32) {
	winDivertHelperNtohIPv6AddressProc.Call(
		uintptr(unsafe.Pointer(&inAddr[0])),
		uintptr(unsafe.Pointer(&outAddr[0])),
	)
}

// Deprecated: un-understandable
func WinDivertHelperNtohIpv6Address(inAddr, outAddr []uint32) {
	winDivertHelperNtohIpv6AddressProc.Call(
		uintptr(unsafe.Pointer(&inAddr[0])),
		uintptr(unsafe.Pointer(&outAddr[0])),
	)
}

func WinDivertHelperNtohl(x uint32) uint32 {
	r1, _, _ := winDivertHelperNtohlProc.Call(
		uintptr(x),
	)
	return uint32(r1)
}

func WinDivertHelperNtohll(x uint64) uint64 {
	r1, _, _ := winDivertHelperNtohllProc.Call(
		uintptr(x),
	)
	return uint64(r1)
}

func WinDivertHelperNtohs(x uint16) uint16 {
	r1, _, _ := winDivertHelperNtohsProc.Call(
		uintptr(x),
	)
	return uint16(r1)
}

// Deprecated: un-understandable
func WinDivertHelperHtonIPv6Address(inAddr, outAddr []uint32) {
	winDivertHelperHtonIPv6AddressProc.Call(
		uintptr(unsafe.Pointer(&inAddr[0])),
		uintptr(unsafe.Pointer(&outAddr[0])),
	)
}

// Deprecated: un-understandable
func WinDivertHelperHtonIpv6Address(inAddr, outAddr []uint32) {
	winDivertHelperHtonIpv6AddressProc.Call(
		uintptr(unsafe.Pointer(&inAddr[0])),
		uintptr(unsafe.Pointer(&outAddr[0])),
	)
}

func WinDivertHelperHtonl(x uint32) uint32 {
	r1, _, _ := winDivertHelperHtonlProc.Call(
		uintptr(x),
	)
	return uint32(r1)
}

func WinDivertHelperHtonll(x uint64) uint64 {
	r1, _, _ := winDivertHelperHtonllProc.Call(
		uintptr(x),
	)
	return uint64(r1)
}

func WinDivertHelperHtons(x uint16) uint16 {
	r1, _, _ := winDivertHelperHtonsProc.Call(
		uintptr(x),
	)
	return uint16(r1)
}
