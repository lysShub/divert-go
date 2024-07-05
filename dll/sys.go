package dll

import (
	"sync/atomic"

	"github.com/pkg/errors"
	"golang.org/x/sys/windows"
)

type SysLazyDll struct {
	windows.LazyDLL
	loaded atomic.Bool
}

var _ LazyDll = (*SysLazyDll)(nil)

func (l *SysLazyDll) NewProc(name string) LazyProc {
	return &sysLazyProcWraper{
		LazyProc: l.LazyDLL.NewProc(name),
		dll:      l.LazyDLL.Name,
	}
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

type sysLazyProcWraper struct {
	*windows.LazyProc
	dll string
}

func (p *sysLazyProcWraper) Find() error {
	err := p.LazyProc.Find()
	if err != nil {
		return errors.WithMessage(err, p.dll)
	}
	return nil
}
