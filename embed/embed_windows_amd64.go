package embed

import (
	_ "embed"

	"github.com/lysShub/go-dll"
)

// https://reqrypt.org/download/WinDivert-2.2.2-A.zip

//go:embed WinDivert64.dll
var DLL dll.MemDLL

//go:embed WinDivert64.sys
var Sys []byte
