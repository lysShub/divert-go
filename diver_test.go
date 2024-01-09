package divert_test

import (
	"testing"

	"github.com/lysShub/go-divert"
	"github.com/lysShub/go-divert/embed"
	"github.com/stretchr/testify/require"
)

// telnet 2a03:2880:f10d:83:face:b00c:0:25de 80
// telnet 142.251.43.14 80

func TestCtx(t *testing.T) {
	var f = "!loopback and tcp and remoteAddr=142.251.43.114 and remotePort=80"

	dll, err := divert.LoadDivert(embed.Amd64)
	require.NoError(t, err)
	defer dll.Release()

	d, err := dll.Open(f, divert.LAYER_NETWORK, 0, divert.FLAG_READ_ONLY)
	require.NoError(t, err)

	// fd := os.NewFile(uintptr(h), "divert")

	// err = fd.SetDeadline(time.Now().Add(time.Second * 10))
	// require.NoError(t, err)

	var b = make([]byte, 1024)
	n, _, err := d.Recv(b)
	require.NoError(t, err, n)
}
