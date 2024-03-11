package divert

import (
	"context"
	"fmt"
	"math/rand"
	"net"
	"net/netip"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/go-ping/ping"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var outboundAddr = func() *Address {
	var addr Address
	addr.SetOutbound(true)
	return &addr
}()
var locIP, inboundAddr = func() (netip.Addr, *Address) {
	ip, idx, err := Gateway(netip.IPv4Unspecified())
	if err != nil {
		panic(err)
	}

	var addr Address
	addr.SetOutbound(false)
	addr.Network().IfIdx = uint32(idx)
	return ip, &addr
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

func Test_Load_DLL(t *testing.T) {
	t.Run("embed", func(t *testing.T) {
		e1 := Load(Mem)
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load(Mem)
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	t.Run("file", func(t *testing.T) {
		e1 := Load("embed\\WinDivert64.dll")
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load("embed\\WinDivert64.dll")
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	t.Run("load-fail", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, err)
	})

	t.Run("load-fail/open", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, err)

		d, err := Open("false", Network, 0, 0)
		require.True(t, errors.Is(err, os.ErrClosed))
		require.Nil(t, d)
	})

	t.Run("load-fail/release", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, err)

		require.NoError(t, Release())
	})

	t.Run("load-fail/load", func(t *testing.T) {
		e1 := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, e1)
		require.NoError(t, Release())

		e := Load(Mem)
		require.NoError(t, e)
		require.NoError(t, Release())
	})

	t.Run("load/load", func(t *testing.T) {
		e1 := Load("embed\\WinDivert64.dll")
		require.NoError(t, e1)

		e2 := Load(Mem)
		require.True(t, errors.Is(e2, ErrLoaded{}))

		require.NoError(t, Release())
	})

	t.Run("release/release", func(t *testing.T) {
		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	t.Run("load/release/release", func(t *testing.T) {
		err := Load(Mem)
		require.NoError(t, err)

		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	t.Run("load/open/release", func(t *testing.T) {
		err := Load(Mem)
		require.NoError(t, err)
		defer Release()

		d1, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d1.Close())

		require.NoError(t, Release())

		_, err = d1.Recv(nil, nil)
		require.True(t, errors.Is(err, os.ErrClosed))
	})

	t.Run("open", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, os.ErrClosed))
	})

	t.Run("load/release/open", func(t *testing.T) {
		err := Load(Mem)
		require.NoError(t, err)
		require.NoError(t, Release())

		d, err := Open("false", Network, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, os.ErrClosed))
	})

}

func Test_Address(t *testing.T) {
	require.NoError(t, Load(Mem))
	defer Release()

	t.Run("flow", func(t *testing.T) {
		go func() {
			time.Sleep(time.Second)
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: []byte{8, 8, 8, 8}, Port: 56})
			require.NoError(t, err)
			defer conn.Close()
			conn.Write([]byte("hello"))
		}()

		f := "remoteAddr=8.8.8.8 and remotePort=56"
		d, err := Open(f, Flow, 0, ReadOnly|Sniff)
		require.NoError(t, err)
		defer d.Close()

		var addr Address
		n, err := d.Recv(nil, &addr)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, Flow, addr.Layer)
		require.Equal(t, FlowEstablishd, addr.Event)
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
		require.Equal(t, fa.LocalAddr(), locIP, fa.LocalAddr().String())
		require.Equal(t, fa.RemoteAddr(), netip.AddrFrom4([4]byte{8, 8, 8, 8}), fa.RemoteAddr().String())
	})

	t.Run("network/recv", func(t *testing.T) {
		f := "loopback"
		d, err := Open(f, Network, 0, ReadOnly|Sniff)
		require.NoError(t, err)
		defer d.Close()

		var b = make([]byte, 1536)
		var addr Address
		n, err := d.Recv(b, &addr)
		require.NoError(t, err)
		require.NotZero(t, n)
		require.Equal(t, Network, addr.Layer)
		require.Equal(t, NetworkPacket, addr.Event)
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
			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()

			b := buildUDP(t, caddr, saddr, []byte(msg))

			n, err := d.Send(b, outboundAddr)
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
	require.NoError(t, Load(Mem))
	defer Release()

	t.Run("close/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Close())

		_, err = d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, os.ErrClosed))
	})

	t.Run("recv/close", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, err = d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, os.ErrClosed))
		}
	})

	t.Run("recv/close/close", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, err = d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, os.ErrClosed))

			require.True(t, errors.Is(d.Close(), os.ErrClosed))
		}
	})

	t.Run("recv/close/close/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			{
				_, err = d.Recv(make([]byte, 1536), nil)
				require.True(t, errors.Is(err, os.ErrClosed))
			}
			{
				require.True(t, errors.Is(d.Close(), os.ErrClosed))
			}
			{
				_, err = d.Recv(make([]byte, 1536), nil)
				require.True(t, errors.Is(err, os.ErrClosed))
			}
		}
	})

	t.Run("shutdown/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Shutdown(Both))

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, os.ErrClosed))
		require.Zero(t, n)
	})

	t.Run("recv/shutdown", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, os.ErrClosed))
		require.Zero(t, n)
	})

	t.Run("recv/shutdown/shutdown", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, os.ErrClosed))
		require.Zero(t, n)

		require.NoError(t, d.Shutdown(Both))
	})

	t.Run("recv/shutdown/shutdown/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		{
			n, err := d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, os.ErrClosed))
			require.Zero(t, n)
		}
		{
			require.NoError(t, d.Shutdown(Both))
		}
		{
			n, err := d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, os.ErrClosed))
			require.Zero(t, n)
		}
	})
}

func Test_Recv(t *testing.T) {
	require.NoError(t, Load(Mem))
	defer Release()

	t.Run("Recv/network/loopback", func(t *testing.T) {
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
				caddr.Port(), saddr.Port(), // NOTICE: loopback packet is outbound packet
			)
			d, err := Open(filter, Network, 0, ReadOnly)
			require.NoError(t, err)

			var b = make([]byte, 1536)
			var addr Address
			n, err := d.Recv(b, &addr)
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

	t.Run("Recv/socket", func(t *testing.T) {
		d, err := Open("udp and remoteAddr=8.8.8.8", Socket, 0, Sniff|ReadOnly)
		require.NoError(t, err)
		defer d.Close()

		go func() {
			time.Sleep(time.Second * 2)

			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: []byte{8, 8, 8, 8}, Port: 56})
			require.NoError(t, err)
			defer conn.Close()
			_, err = conn.Write([]byte("hello"))
			require.NoError(t, err)
		}()

		var addr Address
		n, err := d.Recv(nil, &addr)
		require.NoError(t, err)
		require.Zero(t, n)

		sa := addr.Socket()
		require.Equal(t, netip.AddrFrom4([4]byte{8, 8, 8, 8}), sa.RemoteAddr())
	})

	t.Run("RecvCtx/cancel", func(t *testing.T) {
		d, err := Open("false", Network, 0, ReadOnly)
		require.NoError(t, err)
		defer d.Close()

		ctx, cancel := context.WithCancel(context.Background())
		go func() {
			time.Sleep(time.Second)
			cancel()
		}()

		s := time.Now()
		n, err := d.RecvCtx(ctx, make([]byte, 1536), nil)
		require.True(t, errors.Is(err, context.Canceled))
		require.Zero(t, n)
		require.Less(t, time.Since(s), time.Second+200*time.Millisecond)
	})

	t.Run("RecvCtx/timeout", func(t *testing.T) {
		d, err := Open("false", Network, 0, ReadOnly)
		require.NoError(t, err)
		defer d.Close()

		ctx, _ := context.WithTimeout(context.Background(), time.Second)

		s := time.Now()
		n, err := d.RecvCtx(ctx, make([]byte, 1536), nil)
		require.True(t, errors.Is(err, context.DeadlineExceeded))
		require.Zero(t, n)
		require.Less(t, time.Since(s), time.Second+200*time.Millisecond)
		// t.Log(time.Since(s))
	})

	t.Run("RecvCtx/network", func(t *testing.T) {
		d, err := Open("udp and remoteAddr=8.8.8.8 and remotePort=56", Network, 0, ReadOnly)
		require.NoError(t, err)
		defer d.Close()

		go func() {
			conn, err := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 56})
			require.NoError(t, err)
			defer conn.Close()

			time.Sleep(time.Second)
			_, err = conn.Write([]byte("hello"))
			require.NoError(t, err)
		}()

		var addr Address
		var ip = make([]byte, 1536)
		s := time.Now()
		n, err := d.RecvCtx(context.Background(), ip, &addr)
		require.NoError(t, err)
		iphdr := header.IPv4(ip[:n])
		require.Equal(t, n, int(iphdr.TotalLength()))
		require.Less(t, time.Since(s), time.Second+200*time.Millisecond)
		// t.Log(time.Since(s))
	})
}

func Test_Send(t *testing.T) {
	require.NoError(t, Load(Mem))
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

			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, inboundAddr)
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

			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, inboundAddr)
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

			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, outboundAddr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
		}()

		d, err := Open(
			fmt.Sprintf("icmp.Type=0 and remoteAddr=%s", saddr),
			Network,
			0,
			ReadOnly,
		)
		require.NoError(t, err)
		defer d.Close()
		var b = make([]byte, 1536)
		n, err := d.Recv(b, nil)
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

			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()

			for i := 0; i < 3; i++ {
				_, err := d.Send(b, outboundAddr)
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
	require.NoError(t, Load(Mem))
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

		d, err := Open(filter, Network, 0, ReadOnly)
		require.NoError(t, err)
		defer d.Close()

		var b = make([]byte, 2048)
		n, err := d.Recv(b, nil)
		require.NoError(t, err)
		require.Greater(t, n, 1536)
	})

	t.Run("send", func(t *testing.T) {
		t.Skip()
	})
}

// test priority for recv.
// CONCLUSION: packet alway be handle by higher priority.
func Test_Recv_Priority(t *testing.T) {
	require.NoError(t, Load(Mem))
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, 0)
				require.NoError(t, err)
				defer d.Close()
				_, err = d.RecvCtx(ctx, make([]byte, 1536), nil)
				if err == nil {
					rs.CompareAndSwap(0, int32(p))
				}
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
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err = conn.Write([]byte(msg))
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
		require.NoError(t, ctx.Err())
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, 0)
				require.NoError(t, err)
				defer d.Close()

				_, err = d.RecvCtx(ctx, make([]byte, 1536), nil)
				if err == nil {
					rs.CompareAndSwap(0, int32(p))
				}
			}(int16(pri))
		}

		// ping baidu.com
		for rs.Load() == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
		require.NoError(t, ctx.Err())
	})

	t.Run("loopback/request", func(t *testing.T) {
		var (
			dst = locIP
		)

		var (
			filter                 = fmt.Sprintf("icmp.Type=8 and (localAddr=%s or remoteAddr=%s)", dst, dst)
			hiPriority, loPriority = 2, 1
			rs                     atomic.Int32
		)
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, 0)
				require.NoError(t, err)
				defer d.Close()

				_, err = d.RecvCtx(ctx, make([]byte, 1536), nil)
				require.NoError(t, err)
				if err == nil {
					rs.CompareAndSwap(0, int32(p))
				}
			}(int16(pri))
		}

		for rs.Load() == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
		require.NoError(t, ctx.Err())
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, 0)
				require.NoError(t, err)
				defer d.Close()

				_, err = d.RecvCtx(ctx, make([]byte, 1536), nil)
				if err == nil {
					rs.CompareAndSwap(0, int32(p))
				}
			}(int16(pri))
		}

		for rs.Load() == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			pingOnce(t, dst.String())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rs.Load())
		require.NoError(t, ctx.Err())
	})
}

// test priority for send.
// CONCLUSION: send packet will be handle by equal(random) or lower(always) priority
func Test_Send_Priority(t *testing.T) {
	require.NoError(t, Load(Mem))
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

		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, midPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, Sniff)
				require.NoError(t, err)
				defer d.Close()

				_, err = d.RecvCtx(ctx, make([]byte, 1536), nil)
				if err == nil {
					rs.Add(int32(p))
				}
			}(int16(pri))
		}

		d, err := Open("false", Network, int16(midPriority), WriteOnly)
		require.NoError(t, err)
		defer d.Close()
		for rs.Load() == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err := d.Send(buildUDP(t, src, dst, []byte(msg)), outboundAddr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		require.Contains(t, []int{loPriority, loPriority + midPriority}, int(rs.Load()))
		require.NoError(t, ctx.Err())
	})

	t.Run("inbound", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(netip.MustParseAddr("114.114.114.114"), uint16(randPort()))
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
		ctx, cancel := context.WithTimeout(context.Background(), time.Second*10)
		defer cancel()

		for _, pri := range []int{hiPriority, midPriority, loPriority} {
			go func(p int16) {
				d, err := Open(filter, Network, p, Sniff)
				require.NoError(t, err)
				defer d.Close()

				var b = make([]byte, 1536)
				var addr Address
				_, err = d.RecvCtx(ctx, b, &addr)
				require.NoError(t, err)
				require.True(t, !addr.Flags.Outbound())
				rs.Add(int32(p))
			}(int16(pri))
		}

		d, err := Open("false", Network, int16(midPriority), WriteOnly)
		require.NoError(t, err)
		for rs.Load() == 0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			_, err := d.Send(buildUDP(t, src, dst, []byte(msg)), inboundAddr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		require.Contains(t, []int{loPriority, loPriority + midPriority}, int(rs.Load()))
		require.NoError(t, ctx.Err())
	})
}

func Test_Helper(t *testing.T) {
	require.NoError(t, Load(Mem))
	defer Release()

	t.Run("format/null", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		s, err := HelperFormatFilter("", Network)
		require.True(t, errors.Is(err, windows.ERROR_INVALID_PARAMETER))
		require.Zero(t, len(s))
	})
}
