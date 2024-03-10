package divert

import (
	_ "embed"
)

//go:embed embed/WinDivert32.dll
var dllData []byte

//go:embed embed/WinDivert32.sys
var sysData []byte

var Mem = MemMode{
	DLL: dllData,
	Sys: sysData,
}
