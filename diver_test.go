package divert_test

import (
	"os"
	"testing"
	"time"

	"github.com/lysShub/go-divert"
	"github.com/stretchr/testify/require"
)

// telnet 2a03:2880:f10d:83:face:b00c:0:25de 80
// telnet 142.251.43.14 80

var _ = divert.SetPath(`D:\OneDrive\code\go\go-divert\WinDivert.dll`)

func TestCtx(t *testing.T) {
	var f = "!loopback and tcp and remoteAddr=142.251.43.114 and remotePort=80"

	h, err := divert.Open(f, divert.LAYER_NETWORK, 0, divert.FLAG_READ_ONLY)
	require.NoError(t, err)

	fd := os.NewFile(uintptr(h), "divert")

	err = fd.SetDeadline(time.Now().Add(time.Second * 10))
	require.NoError(t, err)

	var b = make([]byte, 1024)
	n, _, err := h.Recv(b)
	require.NoError(t, err, n)
}
