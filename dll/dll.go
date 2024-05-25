//go:build windows
// +build windows

package dll

import (
	"sync"
	"sync/atomic"

	"golang.org/x/sys/windows"
)

type LazyDll interface {
	Handle() uintptr
	Load() error
	NewProc(name string) LazyProc
}

type LazyProc interface {
	Addr() uintptr
	Call(a ...uintptr) (r1 uintptr, r2 uintptr, lastErr error)
	Find() error
}

type CommLazyDll struct {
	LazyDll
	loaded atomic.Bool
}

func (d *CommLazyDll) Loaded() bool { return d.loaded.Load() }
func (d *CommLazyDll) Load() error {
	if !d.loaded.Load() {
		err := d.LazyDll.Load()
		if err != nil {
			return err
		}
		d.loaded.Store(true)
	}
	return nil
}

func NewLazyDLL[T ~string | ~[]byte](dll T) *CommLazyDll {
	switch dll := any(dll).(type) {
	case string:
		return &CommLazyDll{
			LazyDll: &SysLazyDll{LazyDLL: windows.LazyDLL{Name: dll}},
		}
	case []byte:
		return &CommLazyDll{
			LazyDll: &MemLazyDll{Data: dll},
		}
	default:
		panic("")
	}
}

// ResetLazyDll reset dll before load
func ResetLazyDll[T ~string | ~[]byte](dll *CommLazyDll, src T) {
	if dll.Loaded() {
		panic("cant't reset loaded dll")
	}

	switch src := any(src).(type) {
	case string:
		dll.LazyDll = &SysLazyDll{LazyDLL: windows.LazyDLL{Name: src}}
	case []byte:
		dll.LazyDll = &MemLazyDll{Data: src}
	default:
		panic("")
	}
}

func (d *CommLazyDll) NewProc(name string) LazyProc { return &CommLazyProc{Name: name, dll: d} }

type CommLazyProc struct {
	Name string
	dll  *CommLazyDll

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

		p.proc = p.dll.LazyDll.NewProc(p.Name)
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
