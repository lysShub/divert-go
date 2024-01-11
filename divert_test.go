package divert_test

import (
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/go-divert/embed"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

// telnet 2a03:2880:f10d:83:face:b00c:0:25de 80
// telnet 142.251.43.14 80

var locIP = func() net.IP {
	c, _ := net.DialUDP("udp", nil, &net.UDPAddr{IP: net.ParseIP("8.8.8.8"), Port: 53})
	return (c.LocalAddr().(*net.UDPAddr)).IP
}()

func TestNetworkInstallDriver(t *testing.T) {

	{
		d1, err := divert.LoadDivert(embed.DLL64, embed.Sys64)
		require.NoError(t, err)
		d1.Release()

		d2, err := divert.LoadDivert(embed.DLL64, embed.Sys64)
		require.NoError(t, err)
		d2.Release()
	}

}

func TestNetworkFlow(t *testing.T) {
	dll, err := divert.LoadDivert(embed.DLL64, embed.Sys64)
	require.NoError(t, err)
	defer dll.Release()

	go func() {
		time.Sleep(time.Second)
		http.Get("www.amazon.com")
	}()

	f := "outbound and !loopback"
	d, err := dll.Open(f, divert.LAYER_FLOW, 0, divert.READ_ONLY|divert.SNIFF)
	require.NoError(t, err)
	var _ = windows.ERROR_MOD_NOT_FOUND

	n, addr, err := d.Recv(nil)
	require.NoError(t, err)
	require.Zero(t, n)
	fa := addr.Flow()
	require.True(t, locIP.Equal(fa.LocalAddr().AsSlice()), fa.LocalAddr().String())
}

func TestSend(t *testing.T) {
	// todo
}

func TestCtx(t *testing.T) {
	var f = "!loopback and tcp and remoteAddr=142.251.43.114 and remotePort=80"

	dll, err := divert.LoadDivert(`D:\OneDrive\code\go\go-divert\embed\divert_amd64.dll`, ``)
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
