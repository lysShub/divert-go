package dll

import (
	"golang.org/x/sys/windows"
)

type SysLazyDll struct {
	windows.LazyDLL
}

var _ LazyDll = (*SysLazyDll)(nil)

func (l *SysLazyDll) NewProc(name string) LazyProc {
	return l.LazyDLL.NewProc(name)
}
