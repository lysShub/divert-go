package divert_test

import (
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
		src := locIP
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})
		is := divert.Loopback(src, dst)
		require.False(t, is)
	}

	{
		src := netip.IPv4Unspecified()
		dst := locIP
		is := divert.Loopback(src, dst)
		require.True(t, is)
	}

	{
		src := locIP
		dst := locIP
		is := divert.Loopback(src, dst)
		require.True(t, is)
	}
}

func Test_Gatway(t *testing.T) {
	t.Run("0.0.0.0", func(t *testing.T) {
		src, idx, err := divert.Gateway(netip.IPv4Unspecified())
		require.NoError(t, err)
		require.Equal(t, locIP, src)

		expIdx := getIndex(t, locIP)
		require.Equal(t, expIdx, idx)
	})

	t.Run("127.0.0.1", func(t *testing.T) {
		dst := netip.AddrFrom4([4]byte{127, 0, 0, 1})

		src, idx, err := divert.Gateway(dst)
		require.NoError(t, err)
		require.Equal(t, 1, idx)

		require.Equal(t, src, dst)
	})

	t.Run("baidu.com", func(t *testing.T) {
		dst := func() netip.Addr {
			ips, err := net.LookupIP("baidu.com")
			require.NoError(t, err)
			for _, ip := range ips {
				if ip.To4() != nil {
					return netip.AddrFrom4([4]byte(ip.To4()))
				}
			}
			panic("")
		}()

		src, idx, err := divert.Gateway(dst)
		require.NoError(t, err)
		require.Equal(t, locIP, src)

		expIdx := getIndex(t, locIP)
		require.Equal(t, expIdx, idx)
	})
}

func getIndex(t *testing.T, addr netip.Addr) int {
	ifs, err := net.Interfaces()
	require.NoError(t, err)

	for _, i := range ifs {
		addrs, err := i.Addrs()
		require.NoError(t, err)
		for _, a := range addrs {
			if a, ok := a.(*net.IPNet); ok {
				_, bits := a.Mask.Size()
				if bits == addr.BitLen() {
					if a.IP.To4() != nil {
						if netip.AddrFrom4([4]byte(a.IP.To4())) == addr {
							return i.Index
						}
					} else {
						if netip.AddrFrom16([16]byte(a.IP)) == addr {
							return i.Index
						}
					}
				}
			}
		}
	}
	t.Fatal("not found address")
	return 0
}
