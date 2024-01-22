package divert

import (
	_ "embed"

	"github.com/lysShub/dll-go"
)

// https://reqrypt.org/download/WinDivert-2.2.2-A.zip

//go:embed embed/WinDivert64.dll
var DLL dll.MemDLL

//go:embed embed/WinDivert64.sys
var Sys []byte
