package divert

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Loopback validate the address tuple is windows loopback
func Loopback(src, dst netip.Addr) bool {
	// todo: support ipv6

	if src.IsUnspecified() {
		var err error
		src, _, err = Gateway(dst)
		if err != nil {
			return false
		}
	}
	return src == dst
}

func Gateway(dst netip.Addr) (gateway netip.Addr, ifIdx int, err error) {
	rows, err := GetIpForwardTable()
	if err != nil {
		return netip.Addr{}, 0, err
	}

	next := dst
	for i := range rows {
		if rows[i].DestAddr().Contains(next) {
			if rows[i].NextHop() == next {
				ifIdx = int(rows[i].IfIndex)
				break
			} else {
				next = rows[i].NextHop()
			}
		}
	}
	if ifIdx == 0 {
		return netip.Addr{}, 0, fmt.Errorf("can't find route to destination address %s", dst)
	}

	return next, ifIdx, nil
}

var (
	iphlpapi              = windows.NewLazySystemDLL("iphlpapi.dll")
	procGetIpForwardTable = iphlpapi.NewProc("GetIpForwardTable")
)

// GetIpForwardTable get sorted ip route entries
func GetIpForwardTable() (rows []MibIpRow, err error) {
	/*
		typedef struct _MIB_IPFORWARDTABLE {
		  DWORD            dwNumEntries;
		  MIB_IPFORWARDROW table[ANY_SIZE];
		} MIB_IPFORWARDTABLE, *PMIB_IPFORWARDTABLE;
	*/
	const order uintptr = 1

	var buffSize uint32
	if r1, _, err := syscall.SyscallN(
		procGetIpForwardTable.Addr(),
		0,
		uintptr(unsafe.Pointer(&buffSize)),
		0,
	); syscall.Errno(r1) != windows.ERROR_INSUFFICIENT_BUFFER {
		return nil, err
	}

	var b = make([]byte, buffSize)
	if r1, _, err := syscall.SyscallN(
		procGetIpForwardTable.Addr(),
		uintptr(unsafe.Pointer(unsafe.SliceData(b))),
		uintptr(unsafe.Pointer(&buffSize)),
		order,
	); r1 != 0 {
		if err != windows.DS_S_SUCCESS {
			return nil, err
		}
		return nil, syscall.Errno(r1)
	}

	n := binary.NativeEndian.Uint32(b[:4])
	rows = unsafe.Slice((*MibIpRow)(unsafe.Pointer(&b[4:][0])), n)
	return rows, nil
}

type MibIpRow struct {
	/*
		typedef struct _MIB_IPFORWARDROW {
		  DWORD    dwForwardDest;
		  DWORD    dwForwardMask;
		  DWORD    dwForwardPolicy;
		  DWORD    dwForwardNextHop;
		  IF_INDEX dwForwardIfIndex;
		  union {
		    DWORD              dwForwardType;
		    MIB_IPFORWARD_TYPE ForwardType;
		  };
		  union {
		    DWORD               dwForwardProto;
		    MIB_IPFORWARD_PROTO ForwardProto;
		  };
		  DWORD    dwForwardAge;
		  DWORD    dwForwardNextHopAS;
		  DWORD    dwForwardMetric1;
		  DWORD    dwForwardMetric2;
		  DWORD    dwForwardMetric3;
		  DWORD    dwForwardMetric4;
		  DWORD    dwForwardMetric5;
		} MIB_IPFORWARDROW, *PMIB_IPFORWARDROW;
	*/

	dest      uint32
	mask      uint32
	Policy    uint32
	nextHop   uint32
	IfIndex   uint32
	Type      IPForwardType
	Proto     RouteProto
	Age       uint32
	NextHopAS uint32
	Metric1   uint32
	Metric2   uint32
	Metric3   uint32
	Metric4   uint32
	Metric5   uint32
}

func (r *MibIpRow) DestAddr() netip.Prefix {
	a := binary.NativeEndian.AppendUint32(nil, r.mask)
	ones, _ := net.IPMask(a).Size()

	return netip.PrefixFrom(r.destAddr(), ones)
}

func (r *MibIpRow) destAddr() netip.Addr {
	a := binary.NativeEndian.AppendUint32(nil, r.dest)
	return netip.AddrFrom4([4]byte(a))
}

func (r *MibIpRow) NextHop() netip.Addr {
	a := binary.NativeEndian.AppendUint32(nil, r.nextHop)
	return netip.AddrFrom4([4]byte(a))
}

type IPForwardType uint32

const (
	_ IPForwardType = iota
	OTHER
	INVALID
	DIRECT
	INDIRECT
)

type RouteProto uint32

const (
	_ RouteProto = iota
	Other
	Local
	NetMgmt
	Icmp
	Egp
	Ggp
	Hello
	Rip
	IsIs
	EsIs
	Cisco
	Bbn
	Ospf
	Bgp
	Idpr
	Eigrp
	Dvmrp
	Rpl
	Dhcp
)
