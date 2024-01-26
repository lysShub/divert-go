package divert_test

import (
	"errors"
	"fmt"
	"math/rand"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"testing"
	"time"

	"github.com/lysShub/divert-go"
	"github.com/stretchr/testify/require"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

// telnet 2a03:2880:f10d:83:face:b00c:0:25de 80
// telnet 142.251.43.14 80

var locIP = func() netip.Addr {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
}()

func randPort() int {
	for {
		port := uint16(rand.Uint32())
		if port > 2048 && port < 0xffff-0xff {
			return int(port)
		}
	}
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
			saddr = &net.UDPAddr{IP: locIP.AsSlice(), Port: randPort()}
			caddr = &net.UDPAddr{IP: locIP.AsSlice(), Port: randPort()}
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

		conn, err := net.ListenUDP("udp", saddr)
		require.NoError(t, err)
		defer conn.Close()
		for {
			var b = make([]byte, 1536)
			n, raddr, err := conn.ReadFromUDP(b)
			require.NoError(t, err)
			if raddr.Port == caddr.Port {
				require.Equal(t, msg, string(b[:n]))
				return
			}
		}
	})
}

func buildUDP(t *testing.T, src, dst *net.UDPAddr, payload []byte) []byte {
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
		SrcAddr:        tcpip.AddrFrom4(src.AddrPort().Addr().As4()),
		DstAddr:        tcpip.AddrFrom4(dst.AddrPort().Addr().As4()),
	})
	iphdr.SetChecksum(^checksum.Checksum(b[:iphdr.HeaderLength()], 0))

	udphdr := header.UDP(iphdr.Payload())
	udphdr.Encode(&header.UDPFields{
		SrcPort:  src.AddrPort().Port(),
		DstPort:  dst.AddrPort().Port(),
		Length:   uint16(len(udphdr)),
		Checksum: 0,
	})
	n := copy(udphdr.Payload(), payload)
	require.Equal(t, len(payload), n)

	sum := header.PseudoHeaderChecksum(
		header.UDPProtocolNumber,
		tcpip.AddrFrom4(src.AddrPort().Addr().As4()),
		tcpip.AddrFrom4(dst.AddrPort().Addr().As4()),
		uint16(len(udphdr)),
	)
	udphdr.SetChecksum(^checksum.Checksum(udphdr, sum))
	return b
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

	{ // close
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
	}

	{ // shutdown recv
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Shutdown(divert.RECV))
			}()
			{
				n, _, err := d.Recv(make([]byte, 1536))
				require.NoError(t, err)
				require.Zero(t, n)
			}
			{
				n, _, err := d.Recv(make([]byte, 1536))
				require.NoError(t, err)
				require.Zero(t, n)
			}
			{
				require.NoError(t, d.Close())
				_, _, err = d.Recv(make([]byte, 1536))
				require.True(t, errors.Is(err, net.ErrClosed))
			}
		}
	}

	{ // shutdown both
		d, err := dll.Open("false", divert.LAYER_NETWORK, 0, 0)
		require.NoError(t, err)

		{
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
				n, _, err := d.Recv(make([]byte, 1536))
				require.NoError(t, err)
				require.Zero(t, n)
			}
			{
				require.NoError(t, d.Close())
				_, _, err = d.Recv(make([]byte, 1536))
				require.True(t, errors.Is(err, net.ErrClosed))
			}
		}
	}
}

func Test_Loopback(t *testing.T) {
	// The Loopback flag is set for loopback packets. Note that Windows considers any packet originating from,
	// and destined to, the current machine to be a loopback packet, so loopback packets are not limited to
	// localhost addresses. Note that WinDivert considers loopback packets to be outbound only, and will not
	// capture loopback packets on the inbound path.

	dll, err := divert.LoadDivert(divert.DLL, divert.Sys)
	require.NoError(t, err)
	defer dll.Release()

	t.Run("loopback/default_nic_ip", func(t *testing.T) {

		var (
			saddr = &net.UDPAddr{IP: locIP.AsSlice(), Port: randPort()}
			caddr = &net.UDPAddr{IP: locIP.AsSlice(), Port: randPort()}
			msg   = "hello"
		)

		go func() {
			time.Sleep(time.Second)

			conn, err := net.DialUDP("udp", caddr, saddr)
			require.NoError(t, err)

			n, err := conn.Write([]byte(msg))
			require.NoError(t, err)
			require.Equal(t, len(msg), n)
		}()

		var filter = fmt.Sprintf(
			"loopback and udp and localPort=%d and remotePort=%d",
			caddr.Port, saddr.Port,
		)

		d, err := dll.Open(filter, divert.LAYER_NETWORK, 0, divert.READ_ONLY|divert.SNIFF)
		require.NoError(t, err)

		for {
			var b = make([]byte, 1536)
			n, _, err := d.Recv(b)
			require.NoError(t, err)

			switch header.IPVersion(b) {
			case 4:
				iphdr := header.IPv4(b[:n])
				if iphdr.TransportProtocol() == header.UDPProtocolNumber {
					udphdr := header.UDP(iphdr.Payload())
					if udphdr.SourcePort() == uint16(caddr.Port) &&
						udphdr.DestinationPort() == uint16(saddr.Port) {

						require.Equal(t, msg, string(udphdr.Payload()))
						return
					}
				}
			default:
			}
		}
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
