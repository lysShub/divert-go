//go:build windows
// +build windows

package divert

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/pkg/errors"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func Test_Address(t *testing.T) {
	require.NoError(t, Load(DLL))
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

		go func() {
			time.Sleep(time.Second)
			pingOnce(t, "127.0.0.1")
		}()

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
	require.NoError(t, Load(DLL))
	defer Release()

	t.Run("close/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Close())
		defer d.Close()

		_, err = d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, ErrClosed{}))
	})

	t.Run("recv/close", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, err = d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, ErrClosed{}))
		}
	})

	t.Run("recv/close/close", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			_, err = d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, ErrClosed{}))

			require.True(t, errors.Is(d.Close(), ErrClosed{}))
		}
	})

	t.Run("recv/close/close/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		{
			go func() {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
			}()
			{
				_, err = d.Recv(make([]byte, 1536), nil)
				require.True(t, errors.Is(err, ErrClosed{}))
			}
			{
				require.True(t, errors.Is(d.Close(), ErrClosed{}))
			}
			{
				_, err = d.Recv(make([]byte, 1536), nil)
				require.True(t, errors.Is(err, ErrClosed{}))
			}
		}
	})

	t.Run("shutdown/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d.Shutdown(Both))
		defer d.Close()

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, ErrShutdown{}))
		require.Zero(t, n)
	})

	t.Run("recv/shutdown", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, ErrShutdown{}))
		require.Zero(t, n)
	})

	t.Run("recv/shutdown/shutdown", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, ErrShutdown{}))
		require.Zero(t, n)

		require.NoError(t, d.Shutdown(Both))
	})

	t.Run("recv/shutdown/shutdown/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		go func() {
			time.Sleep(time.Second)
			require.NoError(t, d.Shutdown(Both))
		}()

		{
			n, err := d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, ErrShutdown{}))
			require.Zero(t, n)
		}
		{
			require.NoError(t, d.Shutdown(Both))
		}
		{
			n, err := d.Recv(make([]byte, 1536), nil)
			require.True(t, errors.Is(err, ErrShutdown{}))
			require.Zero(t, n)
		}
	})

	t.Run("close/recv", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		defer d.Close()

		err = d.Close()
		require.NoError(t, err)

		n, err := d.Recv(make([]byte, 1536), nil)
		require.True(t, errors.Is(err, ErrClosed{}))
		require.Zero(t, n)
	})
}

func Test_Recv(t *testing.T) {
	require.NoError(t, Load(DLL))
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

		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()

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
	t.Skip("todo: can't pass github/action, local can pass")

	require.NoError(t, Load(DLL))
	defer Release()

	t.Run("inbound", func(t *testing.T) {
		var (
			caddr = netip.AddrPortFrom(locIP, randPort())
			saddr = netip.AddrPortFrom(netip.AddrFrom4([4]byte{8, 8, 8, 8}), randPort())
			msg   = "hello"
		)

		eg, _ := errgroup.WithContext(context.Background())

		eg.Go(func() error {
			conn, err := net.DialUDP("udp", toUDPAddr(caddr), toUDPAddr(saddr))
			require.NoError(t, err)
			defer conn.Close()

			var b = make([]byte, 1536)
			n, addr, err := conn.ReadFromUDP(b)
			require.NoError(t, err)
			require.Equal(t, msg, string(b[:n]))
			require.Equal(t, saddr.Port(), uint16(addr.Port))
			return nil
		})

		eg.Go(func() error {
			d, err := Open("false", Network, 0, WriteOnly)
			require.NoError(t, err)
			defer d.Close()
			b := buildUDP(t, saddr, caddr, []byte(msg))

			for i := 0; i < 3; i++ {
				_, err = d.Send(b, inboundAddr)
				require.NoError(t, err)
				time.Sleep(time.Second)
			}
			return nil
		})
		eg.Wait()
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
	require.NoError(t, Load(DLL))
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

func Test_Recving_Close(t *testing.T) {
	t.Skip("todo: not support concurrent call")

	require.NoError(t, Load(DLL))
	defer Release()

	wg, _ := errgroup.WithContext(context.Background())

	for i := 0; i < 0xf; i++ {
		wg.Go(func() error {
			d, err := Open("!loopback", Network, 0, ReadOnly)
			require.NoError(t, err)
			defer d.Close()

			wg.Go(func() error {
				time.Sleep(time.Second)
				require.NoError(t, d.Close())
				return nil
			})

			var b = make([]byte, 1536)
			for {
				_, err := d.Recv(b, nil)
				if err != nil {
					if errors.Is(err, ErrClosed{}) {
						return nil
					} else {
						t.Log("recv err: ", err.Error())
					}
				}
			}
		})
	}

	wg.Wait()
}

// CONCLUSION: packet alway be handle by higher priority.
func Test_Recv_Priority(t *testing.T) {
	require.NoError(t, Load(DLL))
	defer Release()

	t.Run("outbound", func(t *testing.T) {
		var (
			hiPriority, loPriority int16 = 2, 1
			first                  atomic.Int32
			filter                 = "outbound and !loopback and ip"
			baidu                  = func() tcpip.Address {
				ips, err := net.LookupIP("baidu.com")
				require.NoError(t, err)
				for _, e := range ips {
					if e = e.To4(); e != nil {
						return tcpip.AddrFrom4([4]byte(e))
					}
				}
				panic("")
			}()
		)

		eg, _ := errgroup.WithContext(context.Background())
		for _, p := range []int16{hiPriority, loPriority} {
			pri := p
			eg.Go(func() error {
				var b = make(header.IPv4, 1536)
				d, err := Open(filter, Network, pri, ReadOnly|Sniff)
				require.NoError(t, err)
				defer d.Close()

				for {
					n, err := d.Recv(b[:cap(b)], nil)
					if err != nil {
						fmt.Println("TotalLength", b.TotalLength(), b.Flags())
					}
					require.NoError(t, err)

					if (b[:n]).DestinationAddress() == baidu {
						first.CompareAndSwap(0, int32(pri))
						break
					}
				}
				return nil
			})
		}

		eg.Go(func() error {
			time.Sleep(time.Second)

			req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", baidu.String()), nil)
			require.NoError(t, err)
			req.Close = true
			req.Host = "baidu.com"
			req.Header["User-Agent"] = []string{"curl"}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			return nil
		})
		eg.Wait()

		require.Equal(t, hiPriority, int16(first.Load()))
	})

	t.Run("inbound", func(t *testing.T) {
		var (
			hiPriority, loPriority int16 = 2, 1
			first                  atomic.Int32
			filter                 = "inbound and !loopback and ip"
			baidu                  = func() tcpip.Address {
				ips, err := net.LookupIP("baidu.com")
				require.NoError(t, err)
				for _, e := range ips {
					if e = e.To4(); e != nil {
						return tcpip.AddrFrom4([4]byte(e))
					}
				}
				panic("")
			}()
		)

		eg, _ := errgroup.WithContext(context.Background())
		for _, p := range []int16{hiPriority, loPriority} {
			pri := p
			eg.Go(func() error {
				var b = make(header.IPv4, 1536)
				d, err := Open(filter, Network, pri, ReadOnly)
				require.NoError(t, err)
				defer d.Close()

				for {
					n, err := d.Recv(b[:cap(b)], nil)
					require.NoError(t, err)

					if (b[:n]).SourceAddress() == baidu {
						first.CompareAndSwap(0, int32(pri))
						break
					}
				}
				return nil
			})
		}

		eg.Go(func() error {
			time.Sleep(time.Second)

			req, err := http.NewRequest("GET", fmt.Sprintf("http://%s", baidu.String()), nil)
			require.NoError(t, err)
			req.Close = true
			req.Host = "baidu.com"
			req.Header["User-Agent"] = []string{"curl"}
			resp, err := http.DefaultClient.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()
			return nil
		})
		eg.Wait()

		require.Equal(t, hiPriority, int16(first.Load()))
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

// CONCLUSION: send packet will be handle by equal(random) or lower(always) priority
func Test_Send_Priority(t *testing.T) {
	require.NoError(t, Load(DLL))
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
