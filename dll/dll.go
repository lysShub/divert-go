//go:build windows
// +build windows

package dll

import (
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

type lazyDLL interface {
	Handle() uintptr
	Load() error
	NewProc(name string) LazyProc
	Loaded() bool
	Release() error
}

type LazyProc interface {
	Addr() uintptr
	Call(a ...uintptr) (r1 uintptr, r2 uintptr, lastErr error)
	Find() error
}

var _ = windows.LazyDLL{}

type LazyDLL struct{ lazyDLL }

func NewLazyDLL[T ~string | ~[]byte](dll T) *LazyDLL {
	switch dll := any(dll).(type) {
	case string:
		return &LazyDLL{
			lazyDLL: &file{LazyDLL: windows.LazyDLL{Name: dll}},
		}
	case []byte:
		return &LazyDLL{
			lazyDLL: &mem{Data: dll},
		}
	default:
		panic("")
	}
}

// ResetLazyDLL reset dll before load
func ResetLazyDLL[T ~string | ~[]byte](dll *LazyDLL, src T) {
	if dll.Loaded() {
		panic("cant't reset loaded dll")
	}

	switch src := any(src).(type) {
	case string:
		dll.lazyDLL = &file{LazyDLL: windows.LazyDLL{Name: src}}
	case []byte:
		dll.lazyDLL = &mem{Data: src}
	default:
		panic("")
	}
}

func (d *LazyDLL) NewProc(name string) LazyProc { return &CommLazyProc{Name: name, dll: d} }

type CommLazyProc struct {
	Name string
	dll  *LazyDLL

	found atomic.Bool
	mu    sync.RWMutex
	proc  LazyProc
}

var _ LazyProc = (*CommLazyProc)(nil)

func (p *CommLazyProc) Addr() uintptr {
	p.mustFind()
	return p.proc.Addr()
}
func (p *CommLazyProc) Call(a ...uintptr) (r1 uintptr, r2 uintptr, lastErr error) {
	p.mustFind()
	return p.proc.Call(a...)
}
func (p *CommLazyProc) Find() error {
	if !p.found.Load() {
		p.mu.Lock()
		defer p.mu.Unlock()
		if p.proc != nil {
			return nil
		}

		p.proc = p.dll.lazyDLL.NewProc(p.Name)
		p.found.Store(true)
	}
	return p.proc.Find()
}
func (p *CommLazyProc) mustFind() {
	err := p.Find()
	if err != nil {
		panic(err)
	}
}
