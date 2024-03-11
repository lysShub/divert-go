package divert

import (
	"net"
	"net/netip"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

// Loopback validate the address tuple is windows loopback
func Loopback(src, dst netip.Addr) bool {
	if src.IsUnspecified() {
		var err error
		if src, _, err = Gateway(dst); err != nil {
			return false
		}
	}
	return src == dst
}

func Gateway(dst netip.Addr) (gateway netip.Addr, ifIdx int, err error) {
	var idx uint32
	if dst.Is4() {
		err = windows.GetBestInterfaceEx(&windows.SockaddrInet4{Addr: dst.As4()}, &idx)
	} else {
		err = windows.GetBestInterfaceEx(&windows.SockaddrInet6{Addr: dst.As16()}, &idx)
	}
	if err != nil {
		return netip.Addr{}, 0, errors.WithStack(err)
	}

	addrs, err := (&net.Interface{Index: int(idx)}).Addrs()
	if err != nil {
		return netip.Addr{}, 0, errors.WithStack(err)
	}
	for _, addr := range addrs {
		if addr, ok := addr.(*net.IPNet); ok {
			if _, bits := addr.Mask.Size(); bits == dst.BitLen() {
				if addr.IP.To4() != nil {
					gateway = netip.AddrFrom4([4]byte(addr.IP.To4()))
				} else {
					gateway = netip.AddrFrom16([16]byte(addr.IP))
				}
				return gateway, int(idx), nil
			}
		}
	}
	return netip.Addr{}, int(idx), errors.Errorf("addapter index %d without valid address", idx)
}
