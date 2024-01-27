package divert_test

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tatsushid/go-fastping"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var locIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

func nicIdx() uint32 {
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
}

func randPort() uint16 {
	for {
		port := uint16(rand.Uint32())
		if port > 2048 && port < 0xffff-0xff {
			return uint16(port)
		}
	}
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
	icmphdr.SetChecksum(^checksum.Checksum(icmphdr, 0))

	return p
}

func Test_Load_DLL(t *testing.T) {
	t.Run("embed", func(t *testing.T) {
		d1, err := divert.LoadDivert(divert.DLL, divert.Sys)
		require.NoError(t, err)
		d1.Release()

		d2, err := divert.LoadDivert(divert.DLL, divert.Sys)
		require.NoError(t, err)
		d2.Release()
	})

	// todo: shutdown auto uninstall driver, need reboot to test

	t.Run("file", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip()
		}

		d1, err := divert.LoadDivert("embed\\WinDivert64.dll", "embed\\WinDivert64.sys")
		require.NoError(t, err)
		d1.Release()

		d2, err := divert.LoadDivert("embed\\WinDivert64.dll", "embed\\WinDivert64.sys")
		require.NoError(t, err)
		d2.Release()
	})

	t.Run("find-proc-faild", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			t.Skip()
		}

		dll, err := divert.LoadDivert("C:\\Windows\\System32\\ws2_32.dll", "embed\\WinDivert64.sys")
		require.NotNil(t, err)
		require.Nil(t, dll)
	})
}

func Test_Address(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	t.Run("flow", func(t *testing.T) {
		go func() {
			time.Sleep(time.Second)
			http.Get("www.amazon.com")
		}()

		f := "outbound and !loopback"
		d, err := dll.Open(f, divert.LAYER_FLOW, 0, divert.READ_ONLY|divert.SNIFF)
		require.NoError(t, err)
		defer d.Close()

		n, addr, err := d.Recv(nil)
		require.NoError(t, err)
		require.Zero(t, n)
		require.Equal(t, divert.LAYER_FLOW, addr.Layer)
		require.Equal(t, divert.FLOW_ESTABLISHED, addr.Event)
		require.True(t, addr.Flags.Sniffed())
		require.False(t, addr.Flags.Loopback())
		require.True(t, addr.Flags.Outbound())
		require.False(t, addr.Flags.Impostor())
		require.False(t, addr.Flags.IPv6())

		// todo: NIC Offload?
		// require.True(t, addr.Flags.IPChecksum())
		// require.True(t, addr.Flags.TCPChecksum())

		// todo: test on C
		// require.True(t, addr.Flags.UDPChecksum())
		fa := addr.Flow()
		require.True(t, locIP == fa.LocalAddr(), fa.LocalAddr().String())
	})

	t.Run("network/recv", func(t *testing.T) {
		f := "loopback"
		d, err := dll.Open(f, divert.LAYER_NETWORK, 0, divert.READ_ONLY|divert.SNIFF)
		require.NoError(t, err)
		defer d.Close()

		var b = make([]byte, 1536)
		n, addr, err := d.Recv(b)
		require.NoError(t, err)
		require.NotZero(t, n)
		require.Equal(t, divert.LAYER_NETWORK, addr.Layer)
		require.Equal(t, divert.NETWORK_PACKET, addr.Event)
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
			d, err := dll.Open("false", divert.LAYER_NETWORK, 0, divert.WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()

			b := buildUDP(t, caddr, saddr, []byte(msg))

			var a divert.Address
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

func Test_Multiple_Close(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
	require.NoError(t, err)

	require.NoError(t, d.Close())
	require.True(t, errors.Is(d.Close(), net.ErrClosed))
}

func Test_Recv_Error(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	t.Run("close/recv", func(t *testing.T) {
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Close())

		_, _, err = d.Recv(make([]byte, 1536))
		require.True(t, errors.Is(err, net.ErrClosed))
	})

	t.Run("recv/close", func(t *testing.T) {
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
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
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
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
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
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
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Shutdown(divert.BOTH))

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("recv/shutdown", func(t *testing.T) {
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(divert.BOTH))
		}()

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)
	})

	t.Run("recv/shutdown/shutdown", func(t *testing.T) {
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(divert.BOTH))
		}()

		n, _, err := d.Recv(make([]byte, 1536))
		require.NoError(t, err)
		require.Zero(t, n)

		require.NoError(t, d.Shutdown(divert.BOTH))
	})

	t.Run("recv/shutdown/shutdown/recv", func(t *testing.T) {
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(divert.BOTH))
		}()

		{
			n, _, err := d.Recv(make([]byte, 1536))
			require.NoError(t, err)
			require.Zero(t, n)
		}
		{
			require.NoError(t, d.Shutdown(divert.BOTH))
		}
		{
			n, _, err := d.Recv(make([]byte, 1536))
			require.NoError(t, err)
			require.Zero(t, n)
		}
	})
}

func Test_Filter(t *testing.T) {
	t.Skip()
	// todo: use icmp
	buildICMPEcho(t, netip.Addr{}, netip.Addr{})
}

func Test_Filter_Loopback(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

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
			d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.READ_ONLY)
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

func Test_Divert_Auto_Handle_DF(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	t.Run("recv", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(locIP, uint16(randPort()))
			dst = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(randPort()))
		)
		go func() {
			time.Sleep(time.Second)

			b := buildUDP(t, src, dst, make([]byte, 1536)) // size must > mtu
			addr := &divert.Address{}
			addr.SetOutbound(true)

			d, err := dll.Open("false", divert.LAYER_NETWORK, 1, divert.WRITE_ONLY)
			require.NoError(t, err)
			defer d.Close()
			_, err = d.Send(b, addr)
			require.NoError(t, err)
		}()

		filter := fmt.Sprintf(
			"udp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
			src.Addr().String(), src.Port(), dst.Addr().String(), dst.Port(),
		)

		d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.READ_ONLY)
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
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

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
			rest                   atomic.Int32
			check                  = func(d *divert.Divert) {
				var b = make([]byte, 1536)
				_, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, addr.Flags.Outbound())
			}
		)

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), 0)
			require.NoError(t, err)
			defer d.Close()
			check(d)
			rest.CompareAndSwap(0, int32(loPriority))
		}()
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), 0)
			require.NoError(t, err)
			defer d.Close()
			check(d)
			rest.CompareAndSwap(0, int32(hiPriority))
		}()

		// send udp packet
		conn, err := net.DialUDP(
			"udp",
			&net.UDPAddr{IP: src.Addr().AsSlice(), Port: int(src.Port())},
			&net.UDPAddr{IP: dst.Addr().AsSlice(), Port: int(dst.Port())},
		)
		require.NoError(t, err)
		defer conn.Close()
		for rest.Load() == 0 {
			_, err = conn.Write([]byte(msg))
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rest.Load())
	})

	t.Run("inbound", func(t *testing.T) {
		ips, err := net.LookupIP("baidu.com")
		require.NoError(t, err)
		var (
			dst = netip.MustParseAddr(ips[0].String())
		)

		var check = func(d *divert.Divert) {
			var b = make([]byte, 1536)
			n, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, !addr.Flags.Outbound())
			iphdr := header.IPv4(b[:n])
			icmphdr := header.ICMPv4(iphdr.Payload())
			require.Equal(t, header.ICMPv4EchoReply, icmphdr.Type())
		}

		// recv inbound
		var (
			filter                 = fmt.Sprintf("inbound and icmp.Type=0 and remoteAddr=%s", dst)
			hiPriority, loPriority = 2, 1
			rest                   atomic.Int32
		)
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(hiPriority))
		}()
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(loPriority))
		}()

		// ping baidu.com
		for rest.Load() == 0 {
			pinger := fastping.NewPinger()
			require.NoError(t, pinger.AddIP(dst.String()))
			require.NoError(t, pinger.Run())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rest.Load())
	})

	// loopback alway outbound packet
	t.Run("loopback/reqest", func(t *testing.T) {
		var (
			dst = locIP
		)

		var check = func(d *divert.Divert) {
			var b = make([]byte, 1536)
			n, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, addr.Flags.Outbound())
			iphdr := header.IPv4(b[:n])
			icmphdr := header.ICMPv4(iphdr.Payload())
			require.Equal(t, header.ICMPv4Echo, icmphdr.Type())
		}

		var (
			filter                 = fmt.Sprintf("icmp.Type=8 and (localAddr=%s or remoteAddr=%s)", dst, dst)
			hiPriority, loPriority = 2, 1
			rest                   atomic.Int32
		)

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(loPriority))
		}()

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(hiPriority))
		}()

		for rest.Load() == 0 {
			pinger := fastping.NewPinger()
			require.NoError(t, pinger.AddIP(dst.String()))
			require.NoError(t, pinger.Run())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rest.Load())
	})

	// loopback alway outbound packet
	t.Run("loopback/reply", func(t *testing.T) {
		var (
			dst = locIP
		)

		var check = func(d *divert.Divert) {
			var b = make([]byte, 1536)
			n, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, addr.Flags.Outbound())
			iphdr := header.IPv4(b[:n])
			icmphdr := header.ICMPv4(iphdr.Payload())
			require.Equal(t, header.ICMPv4EchoReply, icmphdr.Type())
		}

		var (
			filter                 = fmt.Sprintf("icmp.Type=0 and (localAddr=%s or remoteAddr=%s)", dst, dst)
			hiPriority, loPriority = 2, 1
			rest                   atomic.Int32
		)

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(loPriority))
		}()

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), 0)
			require.NoError(t, err)
			defer d.Close()

			check(d)
			rest.CompareAndSwap(0, int32(hiPriority))
		}()

		for rest.Load() == 0 {
			pinger := fastping.NewPinger()
			require.NoError(t, pinger.AddIP(dst.String()))
			require.NoError(t, pinger.Run())
			time.Sleep(time.Second)
		}

		require.Equal(t, int32(hiPriority), rest.Load())
	})
}

// test priority for send.
// CONCLUSION: send packet always be handle by lower priority
func Test_Send_Priority(t *testing.T) {
	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

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
			hiPriority, midPriority, loPriority = 3, 2, 1
			rest                                atomic.Int32
		)

		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), divert.SNIFF)
			require.NoError(t, err)
			defer d.Close()

			var b = make([]byte, 1536)
			_, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, addr.Flags.Outbound())
			rest.Add(int32(hiPriority))
		}()
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), divert.SNIFF)
			require.NoError(t, err)
			defer d.Close()

			var b = make([]byte, 1536)
			_, addr, err := d.Recv(b)
			require.NoError(t, err)
			require.True(t, addr.Flags.Outbound())
			rest.Add(int32(loPriority))
		}()

		d, err := dll.Open("false", divert.LAYER_NETWORK, int16(midPriority), divert.WRITE_ONLY)
		require.NoError(t, err)
		defer d.Close()
		b := buildUDP(t, src, dst, []byte(msg))
		var addr divert.Address
		addr.SetOutbound(true)
		for rest.Load() == 0 {
			_, err := d.Send(b, &addr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		time.Sleep(time.Second * 2)
		require.Equal(t, int32(loPriority), rest.Load())
	})

	t.Run("inbound", func(t *testing.T) {
		var (
			src = netip.AddrPortFrom(netip.MustParseAddr("8.8.8.8"), uint16(randPort()))
			dst = netip.AddrPortFrom(locIP, uint16(randPort()))
			msg = "hello"
		)

		var (
			filter = fmt.Sprintf(
				"inbound and udp and localAddr=%s and localPort=%d and remoteAddr=%s and remotePort=%d",
				dst.Addr(), dst.Port(), src.Addr(), src.Port(),
			)
			hiPriority, midPriority, loPriority = 3, 2, 1
			rest                                atomic.Int32
			check                               = func(d *divert.Divert) {
				var b = make([]byte, 1536)
				_, addr, err := d.Recv(b)
				require.NoError(t, err)
				require.True(t, !addr.Flags.Outbound())
			}
		)
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(hiPriority), divert.SNIFF)
			require.NoError(t, err)
			defer d.Close()
			check(d)
			rest.CompareAndSwap(0, int32(hiPriority))
		}()
		go func() {
			d, err := dll.Open(filter, divert.LAYER_NETWORK, int16(loPriority), divert.SNIFF)
			require.NoError(t, err)
			defer d.Close()
			check(d)
			rest.CompareAndSwap(0, int32(loPriority))
		}()

		d, err := dll.Open("false", divert.LAYER_NETWORK, int16(midPriority), divert.WRITE_ONLY)
		require.NoError(t, err)
		b := buildUDP(t, src, dst, []byte(msg))
		var addr divert.Address
		addr.SetOutbound(false)
		addr.Network().IfIdx = nicIdx()
		for rest.Load() == 0 {
			_, err := d.Send(b, &addr)
			require.NoError(t, err)
			time.Sleep(time.Second)
		}

		time.Sleep(time.Second * 2)
		require.Equal(t, int32(loPriority), rest.Load())
	})
}

func TestCtx(t *testing.T) {
	t.Skip() // todo: support ctx

	var f = "!loopback and tcp and remoteAddr=142.251.43.114 and remotePort=80"

	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	d, err := dll.Open(f, divert.LAYER_NETWORK, 0, divert.READ_ONLY)
	require.NoError(t, err)

	// fd := os.NewFile(uintptr(h), "divert")

	// err = fd.SetDeadline(time.Now().Add(time.Second * 10))
	// require.NoError(t, err)

	var b = make([]byte, 1024)
	n, _, err := d.Recv(b)
	require.NoError(t, err, n)
}
