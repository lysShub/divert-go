//go:build windows
// +build windows

package dll_test

import (
	"testing"

	"github.com/lysShub/divert-go/dll"
)

var (
	test     = dll.NewLazyDLL(make([]byte, 3))
	openProc = test.NewProc("WinDivertOpen")
)

func TestXxx(t *testing.T) {
	dll.ResetLazyDll(test, `D:\OneDrive\code\go\divert-go\embed\WinDivert64.dll`)

	openProc.Find()
}
