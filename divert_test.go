package divert

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-ping/ping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var locIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

var locIPNic = func() uint32 {
	idx, err := func(laddr netip.Addr) (int, error) {
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

				if addr, ok := netip.AddrFromSlice(ip); !ok {
					return 0, fmt.Errorf("invalid IP address %s", ip)
				} else {
					if addr.Is4In6() {
						addr = netip.AddrFrom4(addr.As4())
					}
					if addr == laddr {
						if nic == 0 {
							nic = i.Index
						} else {
							return 0, fmt.Errorf("multiple nic have address %s", addr)
						}
					}
				}
			}
		}

		if nic == 0 {
			return 0, fmt.Errorf("not found nic with %s address", laddr)
		} else {
			return nic, nil
		}
	}(locIP)
	if err != nil {
		panic(err)
	}
	return uint32(idx)
}()

func randPort() uint16 {
	for {
		port := uint16(rand.Uint32())
		if port > 2048 && port < 0xffff-0xff {
			return uint16(port)
		}
	}
}
func toUDPAddr(addr netip.AddrPort) *net.UDPAddr {
	return &net.UDPAddr{
		IP:   addr.Addr().AsSlice(),
		Port: int(addr.Port()),
	}
}

func pingOnce(t *testing.T, dst string) {
	pinger, err := ping.NewPinger(dst)
	require.NoError(t, err)
	pinger.SetPrivileged(true)
	pinger.Timeout = time.Millisecond
	pinger.Count = 1
	require.NoError(t, pinger.Run())
}

func buildUDP(t *testing.T, src, dst netip.AddrPort, payload []byte) []byte {
	var b = make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+len(payload))
	iphdr := header.IPv4(b)
	iphdr.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(b)),
		ID:             uint16(rand.Uint32()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            128,
		Protocol:       uint8(header.UDPProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src.Addr().As4()),
		DstAddr:        tcpip.AddrFrom4(dst.Addr().As4()),
	})
	iphdr.SetChecksum(^checksum.Checksum(b[:iphdr.HeaderLength()], 0))

	udphdr := header.UDP(iphdr.Payload())
	udphdr.Encode(&header.UDPFields{
		SrcPort:  src.Port(),
		DstPort:  dst.Port(),
		Length:   uint16(len(udphdr)),
		Checksum: 0,
	})
	n := copy(udphdr.Payload(), payload)
	require.Equal(t, len(payload), n)

	sum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		tcpip.AddrFrom4(src.Addr().As4()),
		tcpip.AddrFrom4(src.Addr().As4()),
		uint16(len(udphdr)),
	)
	udphdr.SetChecksum(^checksum.Checksum(udphdr, sum))
	return b
}

func buildICMPEcho(t *testing.T, src, dst netip.Addr) []byte {
	var p = make([]byte, 28)

	iphdr := header.IPv4(p)
	iphdr.Encode(&header.IPv4Fields{
		TOS:            0,
		TotalLength:    uint16(len(p)),
		ID:             uint16(rand.Uint32()),
		Flags:          0,
		FragmentOffset: 0,
		TTL:            128,
		Protocol:       uint8(header.ICMPv4ProtocolNumber),
		Checksum:       0,
		SrcAddr:        tcpip.AddrFrom4(src.As4()),
		DstAddr:        tcpip.AddrFrom4(dst.As4()),
	})
	iphdr.SetChecksum(^checksum.Checksum(p[:iphdr.HeaderLength()], 0))
	require.True(t, iphdr.IsChecksumValid())

	icmphdr := header.ICMPv4(iphdr.Payload())
	icmphdr.SetType(header.ICMPv4Echo)
	icmphdr.SetIdent(uint16(rand.Uint32()))
	icmphdr.SetSequence(uint16(rand.Uint32()))
	icmphdr.SetChecksum(^checksum.Checksum(icmphdr, 0))

	return p
}

func TestMain(t *testing.M) {
	refs := divert.refs.Load()
	if refs != 0 {
		panic("before ut not Release()")
	}

	os.Exit(t.Run())
}

func Test_Load_DLL(t *testing.T) {
	t.Run("embed", func(t *testing.T) {
		e1 := Load(DLL, Sys)
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load(DLL, Sys)
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	t.Run("file", func(t *testing.T) {
		e1 := Load("embed\\WinDivert64.dll", "embed\\WinDivert64.sys")
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load("embed\\WinDivert64.dll", "embed\\WinDivert64.sys")
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	t.Run("find-proc-faild", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll", "embed\\WinDivert64.sys")
		require.NotNil(t, err)
	})

	t.Run("reload", func(t *testing.T) {
		e1 := Load("C:\\Windows\\System32\\ws2_32.dll", "embed\\WinDivert64.sys")
		require.NotNil(t, e1)
		require.NoError(t, Release())

		e := Load(DLL, Sys)
		require.NoError(t, e)
		require.NoError(t, Release())
	})

	t.Run("muti-load", func(t *testing.T) {
		e1 := Load("embed\\WinDivert64.dll", "embed\\WinDivert64.sys")
		require.NoError(t, e1)

		e2 := Load(DLL, Sys)
		require.NoError(t, e2)

		require.NoError(t, Release())
	})

	t.Run("relase-without-load", func(t *testing.T) {
		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	t.Run("muti-relase", func(t *testing.T) {
		err := Load(DLL, Sys)
		require.NoError(t, err)

		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	t.Run("release-not-close", func(t *testing.T) {
		e1 := Load(DLL, Sys)
		require.NoError(t, e1)
		defer Release()

		d1, e2 := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, e2)
		require.NoError(t, d1.Close())

		d2, e3 := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, e3)
		defer d2.Close()

		require.Error(t, Release())
	})

	t.Run("open-without-open", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, net.ErrClosed))
	})

	t.Run("open-after-release", func(t *testing.T) {
		err := Load(DLL, Sys)
		require.NoError(t, err)
		require.NoError(t, Release())

		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, net.ErrClosed))
	})

}

func Test_Address(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("flow", func(t *testing.T) {
		go func() {
			time.Sleep(time.Second)
			http.Get("www.amazon.com")
		}()

		f := "outbound and !loopback"
		d, err := Open(f, LAYER_FLOW, 0, READ_ONLY|SNIFF)
		require.NoError(t, err)
		defer d.Close()

		n, addr, err := d.Recv(nil)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, LAYER_FLOW, addr.Layer)
		require.Equal(t, FLOW_ESTABLISHED, addr.Event)
		require.True(t, addr.Flags.Sniffed())
		require.False(t, addr.Flags.Loopback())
		require.True(t, addr.Flags.Outbound())
		require.False(t, addr.Flags.Impostor())
		require.False(t, addr.Flags.IPv6())

		// todo: NIC Offload? test on C.
		// require.True(t, addr.Flags.IPChecksum())
		// require.True(t, addr.Flags.TCPChecksum())
		// require.True(t, addr.Flags.UDPChecksum())
		fa := addr.Flow()
		require.True(t, locIP == fa.LocalAddr(), fa.LocalAddr().String())
	})

	t.Run("network/recv", func(t *testing.T) {
		f := "loopback"
		d, err := Open(f, LAYER_NETWORK, 0, READ_ONLY|SNIFF)
		require.NoError(t, err)
		defer d.Close()

		var b = make([]byte, 1536)
		n, addr, err := d.Recv(b)
		require.NoError(t, err)
		require.NotZero(t, n)
		require.Equal(t, LAYER_NETWORK, addr.Layer)
		require.Equal(t, NETWORK_PACKET, addr.Event)
		require.True(t, addr.Flags.Sniffed())
		require.True(t, addr.Flags.Loopback())
		require.True(t, addr.Flags.Outbound())
		require.False(t, addr.Flags.Impostor())
		require.False(t, addr.Flags.IPv6())
	})

	t.Run("network/send", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
			msg   = "hello"
		)

		go func() {
			time.Sleep(time.Second)
			d, err := Open("false", LAYER_NETWORK, 0, WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			b := buildUDP(t, caddr, saddr, []byte(msg))

			var a Address
			// divert considers loopback packets to be outbound only
			a.SetOutbound(true)

			n, err := d.Send(b, &a)
			require.NoError(t, err)
			require.Equal(t, len(b), n)
		}()

		conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())})
		require.NoError(t, err)
		defer conn.Close()
		for {
			var b = make([]byte, 1536)
			n, raddr, err := conn.ReadFromUDP(b)
			require.NoError(t, err)
			if uint16(raddr.Port) == caddr.Port() {
				require.Equal(t, msg, string(b[:n]))
				return
			}
		}
	})
}

func Test_Recv_Error(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("close/recv", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Close())

		_, _, err = d.Recv(make([]byte, 1536))
		require.True(t, errors.Is(err, net.ErrClosed))
	})

	t.Run("recv/close", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, _, err = d.Recv(make([]byte, 1536))
			require.True(t, errors.Is(err, net.ErrClosed))
		}
	})

	t.Run("recv/close/close", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, _, err = d.Recv(make([]byte, 1536))
			require.True(t, errors.Is(err, net.ErrClosed))

			require.True(t, errors.Is(d.Close(), net.ErrClosed))
		}
	})

	t.Run("recv/close/close/recv", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			{
				_, _, err = d.Recv(make([]byte, 1536))
				require.True(t, errors.Is(err, net.ErrClosed))
			}
			{
				require.True(t, errors.Is(d.Close(), net.ErrClosed))
			}
			{
				_, _, err = d.Recv(make([]byte, 1536))
				require.True(t, errors.Is(err, net.ErrClosed))
			}
		}
	})

	t.Run("shutdown/recv", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Shutdown(BOTH))

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("recv/shutdown", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(BOTH))
		}()

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("recv/shutdown/shutdown", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(BOTH))
		}()

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)

		require.NoError(t, d.Shutdown(BOTH))
	})

	t.Run("recv/shutdown/shutdown/recv", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(BOTH))
		}()

		{
			n, _, err := d.Recv(make([]byte, 1536))
			require.NoError(t, err)
			require.Zero(t, n)
		}
		{
			require.NoError(t, d.Shutdown(BOTH))
		}
		{
			n, _, err := d.Recv(make([]byte, 1536))
			require.NoError(t, err)
			require.Zero(t, n)
		}
	})
}

func Test_Recv_Filter(t *testing.T) {
	t.Skip()
	// todo: use icmp
	buildICMPEcho(t, netip.Addr{}, netip.Addr{})
}

func Test_Recv_Filter_Loopback(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("recv/nic", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
			msg   = "hello"
		)

		// client send
		go func() {
			time.Sleep(time.Second)

			conn, err := net.DialUDP(
				"udp",
				&net.UDPAddr{IP: caddr.Addr().AsSlice(), Port: int(caddr.Port())},
				&net.UDPAddr{IP: saddr.Addr().AsSlice(), Port: int(saddr.Port())},
			)
			require.NoError(t, err)

			n, err := conn.Write([]byte(msg))
			require.NoError(t, err)
			require.Equal(t, len(msg), n)
		}()

		{ // server recv
			var filter = fmt.Sprintf(
				"udp and localPort=%d and remotePort=%d",
				caddr.Port(), saddr.Port(), // notice: local is client
			)
			d, err := Open(filter, LAYER_NETWORK, 0, READ_ONLY)
			require.NoError(t, err)

			var b = make([]byte, 1536)
			n, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, addr.Flags.Outbound())
			iphdr := header.IPv4(b[:n])
			udphdr := header.UDP(iphdr.Payload())

			ok := udphdr.SourcePort() == caddr.Port() &&
				udphdr.DestinationPort() == saddr.Port() &&
				assert.Equal(t, msg, string(udphdr.Payload()))

			require.True(t, ok)
		}
	})
}

func Test_Send(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("inbound", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), randPort())
			msg   = "hello"
		)

		// client
		go func() {
			b := buildUDP(t, caddr, saddr, []byte(msg))

			d, err := Open("false", LAYER_NETWORK, 0, WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			var addr Address
			addr.SetOutbound(false)
			addr.Network().IfIdx = locIPNic

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, &addr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
		}()

		conn, err := net.DialUDP("udp", toUDPAddr(saddr), toUDPAddr(caddr))
		require.NoError(t, err)
		defer conn.Close()

		var b = make([]byte, 1536)
		n, addr, err := conn.ReadFromUDP(b)
		require.NoError(t, err)
		require.Equal(t, msg, string(b[:n]))
		require.Equal(t, caddr.Port(), uint16(addr.Port))
	})

	t.Run("inbound/loopback", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
			msg   = "hello"
		)

		// client
		go func() {
			b := buildUDP(t, caddr, saddr, []byte(msg))

			d, err := Open("false", LAYER_NETWORK, 0, WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			var addr Address
			addr.SetOutbound(false)
			addr.Network().IfIdx = locIPNic

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, &addr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
		}()

		conn, err := net.DialUDP("udp", toUDPAddr(saddr), toUDPAddr(caddr))
		require.NoError(t, err)
		defer conn.Close()

		var b = make([]byte, 1536)
		n, addr, err := conn.ReadFromUDP(b)
		require.NoError(t, err)
		require.Equal(t, msg, string(b[:n]))
		require.Equal(t, caddr.Port(), uint16(addr.Port))
	})

	t.Run("outbound", func(t *testing.T) {
		ips, err := net.LookupIP("baidu.com")
		require.NoError(t, err)
		var (
			saddr = netip.AddrFrom4([4]byte(ips[0]))
			caddr = locIP
		)

		go func() {
			b := buildICMPEcho(t, caddr, saddr)

			d, err := Open("false", LAYER_NETWORK, 0, WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			var addr Address
			addr.SetOutbound(true)
			for i := 0; i < 3; i++ {
				_, err := d.Send(b, &addr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
		}()

		d, err := Open(
			fmt.Sprintf("icmp.Type=0 and remoteAddr=%s", saddr),
			LAYER_NETWORK,
			0,
			READ_ONLY,
		)
		require.NoError(t, err)
		defer d.Close()
		var b = make([]byte, 1536)
		n, _, err := d.Recv(b)
		require.NoError(t, err)
		require.NotZero(t, n)
	})

	t.Run("outbound/loopback", func(t *testing.T) {
		var (
			saddr = netip.AddrPortFrom(locIP, randPort())
			caddr = netip.AddrPortFrom(locIP, randPort())
			msg   = "hello"
		)

		// client
		go func() {
			b := buildUDP(t, caddr, saddr, []byte(msg))

			d, err := Open("false", LAYER_NETWORK, 0, WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			var addr Address
			addr.SetOutbound(true)

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, &addr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
		}()

		conn, err := net.DialUDP("udp", toUDPAddr(saddr), toUDPAddr(caddr))
		require.NoError(t, err)
		defer conn.Close()

		var b = make([]byte, 1536)
		n, addr, err := conn.ReadFromUDP(b)
		require.NoError(t, err)
		require.Equal(t, msg, string(b[:n]))
		require.Equal(t, caddr.Port(), uint16(addr.Port))
	})
}

func Test_Auto_Handle_DF(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("recv", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(locIP, uint16(randPort()))
			dst = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(randPort()))
		)
		go func() {
			conn, err := net.DialUDP("udp", toUDPAddr(src), toUDPAddr(dst))
			require.NoError(t, err)

			b := make([]byte, 1536) // todo: get mtu
			for i := 0; i < 3; i++ {
				n, err := conn.Write(b)
				require.NoError(t, err)
				require.Equal(t, n, len(b))
				time.Sleep(time.Second)
			}
		}()

		filter := fmt.Sprintf(
			"udp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
			src.Addr().String(), src.Port(), dst.Addr().String(), dst.Port(),
		)

		d, err := Open(filter, LAYER_NETWORK, 0, READ_ONLY)
		require.NoError(t, err)
		defer d.Close()

		var b = make([]byte, 2048)
		n, _, err := d.Recv(b)
		require.NoError(t, err)
		require.Greater(t, n, 1536)
	})

	t.Run("send", func(t *testing.T) {
		t.Skip()
	})
}

// test priority for recv.
// CONCLUSION: packet alway be handel by higher priority.
func Test_Recv_Priority(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("outbound", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(locIP, uint16(randPort()))
			dst = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(randPort()))
			msg = "hello"
		)

		var (
			filter = fmt.Sprintf(
				"outbound and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
				src.Addr(), src.Port(), dst.Addr(), dst.Port(),
			)
			hiPriority, loPriority = 2, 1
			rs                     atomic.Int32
		)

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, 0)
				require.NoError(t, err)
				defer d.Close()
				var b = make([]byte, 1536)
				_, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, addr.Flags.Outbound())
				rs.CompareAndSwap(0, int32(p))
			}(int16(pri))
		}

		// send udp packet
		conn, err := net.DialUDP(
			"udp",
			&net.UDPAddr{IP: src.Addr().AsSlice(), Port: int(src.Port())},
			&net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())},
		)
		require.NoError(t, err)
		defer conn.Close()
		for rs.Load() == 0 {
			_, err = conn.Write([]byte(msg))
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
	})

	t.Run("inbound", func(t *testing.T) {
		ips, err := net.LookupIP("baidu.com")
		require.NoError(t, err)
		var (
			dst = netip.MustParseAddr(ips[0].String())
		)

		// recv inbound
		var (
			filter                 = fmt.Sprintf("inbound and icmp.Type=0 and remoteAddr=%s", dst)
			hiPriority, loPriority = 2, 1
			rs                     atomic.Int32
		)

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, 0)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				n, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, !addr.Flags.Outbound())
				iphdr := header.IPv4(b[:n])
				icmphdr := header.ICMPv4(iphdr.Payload())
				require.Equal(t, header.ICMPv4EchoReply, icmphdr.Type())
				rs.CompareAndSwap(0, int32(p))
			}(int16(pri))
		}

		// ping baidu.com
		for rs.Load() == 0 {
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
	})

	// loopback alway outbound packet
	t.Run("loopback/reqest", func(t *testing.T) {
		var (
			dst = locIP
		)

		var (
			filter                 = fmt.Sprintf("icmp.Type=8 and (localAddr=%s or remoteAddr=%s)", dst, dst)
			hiPriority, loPriority = 2, 1
			rs                     atomic.Int32
		)

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, 0)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				n, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, addr.Flags.Outbound())
				iphdr := header.IPv4(b[:n])
				icmphdr := header.ICMPv4(iphdr.Payload())
				require.Equal(t, header.ICMPv4Echo, icmphdr.Type())
				rs.CompareAndSwap(0, int32(p))
			}(int16(pri))
		}

		for rs.Load() == 0 {
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
	})

	// loopback alway outbound packet
	t.Run("loopback/reply", func(t *testing.T) {
		var (
			dst = locIP
		)

		var (
			filter                 = fmt.Sprintf("icmp.Type=0 and (localAddr=%s or remoteAddr=%s)", dst, dst)
			hiPriority, loPriority = 2, 1
			rs                     atomic.Int32
		)

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, 0)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				n, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, addr.Flags.Outbound())
				iphdr := header.IPv4(b[:n])
				icmphdr := header.ICMPv4(iphdr.Payload())
				require.Equal(t, header.ICMPv4EchoReply, icmphdr.Type())
				rs.CompareAndSwap(0, int32(p))
			}(int16(pri))
		}

		for rs.Load() == 0 {
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
	})
}

// test priority for send.
// CONCLUSION: send packet always be handle by lower priority
func Test_Send_Priority(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("outbound", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(locIP, uint16(randPort()))
			dst = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(randPort()))
			msg = "hello"
		)

		var (
			filter = fmt.Sprintf(
				"outbound and udp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
				src.Addr(), src.Port(), dst.Addr(), dst.Port(),
			)
			hiPriority, midPriority, loPriority = 4, 2, 1
			rs                                  atomic.Int32
		)

		for _, pri := range []int{hiPriority, midPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, SNIFF)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				_, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, addr.Flags.Outbound())
				rs.Add(int32(p))
			}(int16(pri))
		}

		d, err := Open("false", LAYER_NETWORK, int16(midPriority), WRITE_ONLY)
		require.NoError(t, err)
		defer d.Close()
		var addr Address
		addr.SetOutbound(true)
		for rs.Load() == 0 {
			_, err := d.Send(buildUDP(t, src, dst, []byte(msg)), &addr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		time.Sleep(time.Second * 2)
		require.Equal(t, int32(loPriority), rs.Load())
	})

	t.Run("inbound", func(t *testing.T) {
		var (
			// netip.MustParseAddr("114.114.114.114")
			src = netip.AddrPortFrom(locIP, uint16(randPort()))
			dst = netip.AddrPortFrom(locIP, uint16(randPort()))
			msg = "hello"
		)

		var (
			filter = fmt.Sprintf(
				"inbound and udp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
				dst.Addr(), dst.Port(), src.Addr(), src.Port(),
			)
			hiPriority, midPriority, loPriority = 4, 2, 1
			rs                                  atomic.Int32
		)
		for _, pri := range []int{hiPriority, midPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, LAYER_NETWORK, p, SNIFF)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				_, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, !addr.Flags.Outbound())
				rs.Add(int32(p))
			}(int16(pri))
		}

		d, err := Open("false", LAYER_NETWORK, int16(midPriority), WRITE_ONLY)
		require.NoError(t, err)
		var addr Address
		addr.SetOutbound(false)
		addr.Network().IfIdx = locIPNic
		for rs.Load() == 0 {
			_, err := d.Send(buildUDP(t, src, dst, []byte(msg)), &addr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		time.Sleep(time.Second * 2)
		require.Equal(t, int32(loPriority), rs.Load())
	})
}

func Test_Helper(t *testing.T) {
	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	t.Run("format/null", func(t *testing.T) {
		d, err := Open("false", LAYER_NETWORK, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		s, err := d.HelperFormatFilter("", LAYER_NETWORK)
		require.True(t, errors.Is(err, windows.ERROR_INVALID_PARAMETER))
		require.Zero(t, len(s))
	})
	// todo:
}

func TestCtx(t *testing.T) {
	t.Skip() // todo: support ctx

	var f = "!loopback and tcp and remoteAddr=142.251.43.114 and remotePort=80"

	err := Load(DLL, Sys)
	require.NoError(t, err)
	defer Release()

	d, err := Open(f, LAYER_NETWORK, 0, READ_ONLY)
	require.NoError(t, err)

	// fd := os.NewFile(uintptr(h), "divert")

	// err = fd.SetDeadline(time.Now().Add(time.Second * 10))
	// require.NoError(t, err)

	var b = make([]byte, 1024)
	n, _, err := d.Recv(b)
	require.NoError(t, err, n)
}
