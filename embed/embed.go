package embed

import (
	_ "embed"

	"github.com/lysShub/go-dll"
)

// https://reqrypt.org/download/WinDivert-2.2.2-A.zip

//go:embed divert_amd64.dll
var Amd64 dll.MemDLL

//go:embed divert_x86.dll
var X86 dll.MemDLL
