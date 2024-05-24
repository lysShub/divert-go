//go:build windows
// +build windows

package divert

import (
	"math/rand"
	"net"
	"net/netip"
	"os/exec"
	"testing"
	"time"

	"github.com/pkg/errors"

	"github.com/go-ping/ping"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/checksum"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

var path = "embed\\WinDivert64.dll"

func Test_Gofmt(t *testing.T) {
	cmd := exec.Command("cmd", "/C", "gofmt", "-l", "-w", `.`)
	out, err := cmd.CombinedOutput()

	require.NoError(t, err)
	require.Empty(t, string(out))
}

func Test_Load_DLL(t *testing.T) {
	runLoad(t, "embed", func(t *testing.T) {
		e1 := Load(DLL)
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load(DLL)
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	runLoad(t, "file", func(t *testing.T) {
		e1 := Load(path)
		require.NoError(t, e1)
		require.NoError(t, Release())

		e2 := Load(path)
		require.NoError(t, e2)
		require.NoError(t, Release())
	})

	runLoad(t, "load-fail", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, err)
	})

	runLoad(t, "load-fail/open", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.Error(t, err)

		d, err := Open("false", Network, 0, 0)
		require.True(t, errors.Is(err, ErrNotLoad{}))
		require.Nil(t, d)
	})

	runLoad(t, "load-fail/release", func(t *testing.T) {
		err := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, err)

		require.NoError(t, Release())
	})

	runLoad(t, "load-fail/load", func(t *testing.T) {
		e1 := Load("C:\\Windows\\System32\\ws2_32.dll")
		require.NotNil(t, e1)
		require.NoError(t, Release())

		e := Load(DLL)
		require.NoError(t, e)
		require.NoError(t, Release())
	})

	runLoad(t, "load/load", func(t *testing.T) {
		e1 := Load(path)
		require.NoError(t, e1)

		e2 := Load(DLL)
		require.True(t, errors.Is(e2, ErrLoaded{}))

		require.NoError(t, Release())
	})

	runLoad(t, "release/release", func(t *testing.T) {
		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	runLoad(t, "load/release/release", func(t *testing.T) {
		err := Load(DLL)
		require.NoError(t, err)

		require.NoError(t, Release())
		require.NoError(t, Release())
	})

	runLoad(t, "load/open/release", func(t *testing.T) {
		err := Load(DLL)
		require.NoError(t, err)
		defer Release()

		d1, err := Open("false", Network, 0, 0)
		require.NoError(t, err)
		require.NoError(t, d1.Close())

		require.NoError(t, Release())

		_, err = d1.Recv(nil, nil)
		require.True(t, errors.Is(err, ErrNotLoad{}))
	})

	runLoad(t, "open", func(t *testing.T) {
		d, err := Open("false", Network, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, ErrNotLoad{}))
	})

	runLoad(t, "load/release/open", func(t *testing.T) {
		err := Load(DLL)
		require.NoError(t, err)
		require.NoError(t, Release())

		d, err := Open("false", Network, 0, 0)
		require.Nil(t, d)
		require.True(t, errors.Is(err, ErrNotLoad{}))
	})
}

func runLoad(t *testing.T, name string, fn func(t *testing.T)) {
	t.Run(name, func(t *testing.T) {
		fn(t)
		Release()
	})
}

func Test_MustLoad_DLL(t *testing.T) {
	runLoad(t, "embed", func(t *testing.T) {
		MustLoad(DLL)
		Release()

		MustLoad(DLL)

		MustLoad(DLL)
	})

	runLoad(t, "file", func(t *testing.T) {
		MustLoad(path)
		Release()

		MustLoad(path)

		MustLoad(path)
	})

	runLoad(t, "load-fail", func(t *testing.T) {
		defer func() {
			e := recover()
			require.NotNil(t, e, e)
		}()

		MustLoad("C:\\Windows\\System32\\ws2_32.dll")
	})
}

func Test_Helper(t *testing.T) {
	require.NoError(t, Load(DLL))
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

var outboundAddr = func() *Address {
	var addr Address
	addr.SetOutbound(true)
	return &addr
}()
var locIP, inboundAddr = func() (netip.Addr, *Address) {
	locip := func() netip.Addr {
		c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
		return netip.MustParseAddrPort(c.LocalAddr().String()).Addr()
	}()

	ifidx := func(t *testing.T, addr netip.Addr) int {
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
	}(&testing.T{}, locip)

	var addr Address
	addr.SetOutbound(false)
	addr.Network().IfIdx = uint32(ifidx)
	return locip, &addr
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
