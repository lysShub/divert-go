package divert

import (
	_ "embed"
)

//go:embed embed/WinDivert64.dll
var dllData []byte

//go:embed embed/WinDivert64.sys
var sysData []byte

// from https://reqrypt.org/download/WinDivert-2.2.2-A.zip
var DLL = Mem{
	DLL: dllData,
	Sys: sysData,
}
