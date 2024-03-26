package divert

import (
	_ "embed"
)

// https://reqrypt.org/download/WinDivert-2.2.2-A.zip

//go:embed embed/WinDivert64.dll
var dllData []byte

//go:embed embed/WinDivert64.sys
var sysData []byte

var DLL = Mem{
	DLL: dllData,
	Sys: sysData,
}
