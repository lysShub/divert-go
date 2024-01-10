package embed

import (
	_ "embed"

	"github.com/lysShub/go-dll"
)

// https://reqrypt.org/download/WinDivert-2.2.2-A.zip

//go:embed divert_amd64.dll
var DLL64 dll.MemDLL

//go:embed divert_x86.dll
var DLL32 dll.MemDLL

//go:embed WinDivert32.sys
var Sys32 []byte

//go:embed WinDivert64.sys
var Sys64 []byte
