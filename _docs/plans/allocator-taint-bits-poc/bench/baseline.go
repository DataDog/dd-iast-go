package bench

import (
	"sync"
	"unsafe"
)

// mapStore models the exact-key index of internal/taint/store on the
// taint-tracking branch (256 shards x 128 slots, TryRLock, linear probe).
// It is the "external storage" baseline for the quick check.
type slot struct {
	pointer, length uintptr
}

type shard struct {
	mu    sync.RWMutex
	slots [128]slot
	_     [64]byte
}

type mapStore struct {
	shards [256]shard
}

func hash(p, n uintptr) uint64 {
	h := uint64(p)*0x9e3779b97f4a7c15 ^ uint64(n)*0xc2b2ae3d27d4eb4f
	return h ^ h>>29
}

func (m *mapStore) add(p, n uintptr) {
	h := hash(p, n)
	sh := &m.shards[h&255]
	sh.mu.Lock()
	start := uint8(h >> 8)
	for i := 0; i < 64; i++ {
		s := &sh.slots[(start+uint8(i))%128]
		if s.pointer == 0 {
			*s = slot{p, n}
			break
		}
	}
	sh.mu.Unlock()
}

func (m *mapStore) mayContain(p, n uintptr) bool {
	h := hash(p, n)
	sh := &m.shards[h&255]
	if !sh.mu.TryRLock() {
		return false
	}
	defer sh.mu.RUnlock()
	start := uint8(h >> 8)
	for i := 0; i < 64; i++ {
		s := &sh.slots[(start+uint8(i))%128]
		if s.pointer == 0 {
			return false
		}
		if s.pointer == p && s.length == n {
			return true
		}
	}
	return false
}

func (m *mapStore) mayContainString(s string) bool {
	return m.mayContain(uintptr(unsafe.Pointer(unsafe.StringData(s))), uintptr(len(s)))
}
