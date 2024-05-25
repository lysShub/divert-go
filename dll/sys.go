package dll

import (
	"sync/atomic"

	"golang.org/x/sys/windows"
)

type SysLazyDll struct {
	windows.LazyDLL
	loaded atomic.Bool
}

var _ LazyDll = (*SysLazyDll)(nil)

func (l *SysLazyDll) NewProc(name string) LazyProc {
	return l.LazyDLL.NewProc(name)
}
func (l *SysLazyDll) Load() error {
	if !l.loaded.Load() {
		err := l.LazyDLL.Load()
		if err != nil {
			return err
		}
		l.loaded.Store(true)
	}
	return nil
}
func (l *SysLazyDll) Loaded() bool { return l.loaded.Load() }
