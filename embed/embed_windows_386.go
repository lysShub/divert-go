package embed

import (
	_ "embed"

	"github.com/lysShub/go-dll"
)

//go:embed WinDivert32.dll
var DLL dll.MemDLL

//go:embed WinDivert32.sys
var Sys []byte
