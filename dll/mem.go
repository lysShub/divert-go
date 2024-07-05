package dll

import (
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"github.com/pkg/errors"
	"golang.zx2c4.com/wireguard/windows/driver/memmod"
)

type MemLazyDll struct {
	Data []byte

	mu  sync.RWMutex
	dll *memmod.Module
}

var _ LazyDll = (*MemLazyDll)(nil)

func (d *MemLazyDll) Handle() uintptr {
	d.mustLoad()
	return d.dll.BaseAddr()
}
func (d *MemLazyDll) Load() (err error) {
	if atomic.LoadPointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll))) != nil {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.dll != nil {
		return nil
	}

	dll, err := memmod.LoadLibrary(d.Data)
	if err != nil {
		return errors.WithStack(err)
	}
	atomic.SwapPointer((*unsafe.Pointer)(unsafe.Pointer(&d.dll)), unsafe.Pointer(dll))
	return nil
}
func (d *MemLazyDll) mustLoad() {
	err := d.Load()
	if err != nil {
		panic(err)
	}
}

func (d *MemLazyDll) NewProc(name string) LazyProc {
	return &MemLazyProc{Name: name, l: d}
}
func (d *MemLazyDll) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.dll != nil
}

type MemLazyProc struct {
	Name string

	mu   sync.Mutex
	l    *MemLazyDll
	proc uintptr
}

func (p *MemLazyProc) Addr() uintptr {
	p.mustFind()
	return p.proc
}
func (p *MemLazyProc) Call(a ...uintptr) (r1 uintptr, r2 uintptr, lastErr error) {
	p.mustFind()
	return syscall.SyscallN(p.Addr(), a...)
}
func (p *MemLazyProc) Find() error {
	if atomic.LoadUintptr(&p.proc) == 0 {
		p.mu.Lock()
		defer p.mu.Unlock()

		if p.proc == 0 {
			err := p.l.Load()
			if err != nil {
				return err
			}

			proc, err := p.l.dll.ProcAddressByName(p.Name)
			if err != nil {
				return err
			}
			atomic.StoreUintptr(&p.proc, proc)
		}
	}
	return nil
}
func (p *MemLazyProc) mustFind() {
	if err := p.Find(); err != nil {
		panic(err)
	}
}
