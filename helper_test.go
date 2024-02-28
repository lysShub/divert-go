package divert_test

import (
	"fmt"
	"net"
	"net/netip"
	"testing"

	"github.com/lysShub/divert-go"
	"github.com/stretchr/testify/require"
)

var locIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

func Test_Loopback(t *testing.T) {
	{
		src := netip.IPv4Unspecified()
		dst := netip.IPv4Unspecified()
		is := divert.Loopback(src, dst)
		require.False(t, is)
	}

	{
		src := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		is := divert.Loopback(src, dst)
		require.True(t, is)
	}

	{
		src := netip.IPv4Unspecified()
		dst := locIP
		is := divert.Loopback(src, dst)
		require.True(t, is)
	}
}

func Test_Gatway(t *testing.T) {

	addr, idx, err := divert.Gateway(netip.IPv4Unspecified())
	require.NoError(t, err)
	require.Equal(t, locIP, addr)

	expIdx, err := getNICIndex(locIP)
	require.NoError(t, err)
	require.Equal(t, expIdx, idx)
}

func getNICIndex(addr netip.Addr) (int, error) {
	ifs, err := net.Interfaces()
	if err != nil {
		return 0, err
	}

	nic := 0
	for _, i := range ifs {
		as, err := i.Addrs()
		if err != nil {
			return 0, err
		}
		for _, a := range as {
			var ip net.IP
			switch a := a.(type) {
			case *net.IPAddr:
				ip = a.IP
			case *net.IPNet:
				ip = a.IP
			default:
				return 0, fmt.Errorf("unknow address type %T", a)
			}

			if a, ok := netip.AddrFromSlice(ip); !ok {
				return 0, fmt.Errorf("invalid IP address %s", ip)
			} else {
				if a.Is4In6() {
					a = netip.AddrFrom4(a.As4())
				}
				if a == addr {
					if nic == 0 {
						nic = i.Index
					} else {
						return 0, fmt.Errorf("multiple nic have address %s", a)
					}
				}
			}
		}
	}

	if nic == 0 {
		return 0, fmt.Errorf("not found nic with %s address", addr)
	} else {
		return nic, nil
	}
}
