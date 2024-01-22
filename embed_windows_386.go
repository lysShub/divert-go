package divert

import (
	_ "embed"

	"github.com/lysShub/dll-go"
)

//go:embed embed/WinDivert32.dll
var DLL dll.MemDLL

//go:embed embed/WinDivert32.sys
var Sys []byte
