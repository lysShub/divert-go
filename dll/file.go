package dll

import (
	"sync/atomic"

	"golang.org/x/sys/windows"
)

type file struct {
	windows.LazyDLL
	loaded atomic.Bool
}

var _ lazyDLL = (*file)(nil)

func (l *file) NewProc(name string) LazyProc {
	return l.LazyDLL.NewProc(name)
}
func (l *file) Load() error {
	if !l.loaded.Load() {
		err := l.LazyDLL.Load()
		if err != nil {
			return err
		}
		l.loaded.Store(true)
	}
	return nil
}
func (l *file) Loaded() bool { return l.loaded.Load() }
