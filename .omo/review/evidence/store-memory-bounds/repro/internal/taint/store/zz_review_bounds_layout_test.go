package store

import (
	"runtime"
	"testing"
	"unsafe"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func boundsHeap() uint64 {
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapInuse
}

func TestBoundsFixedLayout(t *testing.T) {
	t.Logf("Range=%d Set=%d valueSlot=%d rootRecord=%d binding=%d bindingTable=%d WriterView=%d writerRecord=%d owner=%d shard=%d overflowBlock=%d Store=%d Snapshot=%d Owner=%d",
		unsafe.Sizeof(ranges.Range{}), unsafe.Sizeof(ranges.Set{}), unsafe.Sizeof(valueSlot{}),
		unsafe.Sizeof(rootRecord{}), unsafe.Sizeof(binding{}), unsafe.Sizeof(bindingTable{}),
		unsafe.Sizeof(WriterView{}), unsafe.Sizeof(writerRecord{}), unsafe.Sizeof(owner{}),
		unsafe.Sizeof(shard{}), unsafe.Sizeof(overflowBlock{}), unsafe.Sizeof(Store{}),
		unsafe.Sizeof(Snapshot{}), unsafe.Sizeof(Owner{}))
	t.Logf("fixed components shards=%d owners=%d overflow=%d overflowFree=%d other=%d",
		unsafe.Sizeof(Store{}.shards), unsafe.Sizeof(Store{}.owners),
		unsafe.Sizeof(Store{}.overflow), unsafe.Sizeof(Store{}.overflowFree),
		unsafe.Sizeof(Store{})-unsafe.Sizeof(Store{}.shards)-unsafe.Sizeof(Store{}.owners)-unsafe.Sizeof(Store{}.overflow)-unsafe.Sizeof(Store{}.overflowFree))
	before := boundsHeap()
	s := New()
	after := boundsHeap()
	t.Logf("fixed heap before=%d after=%d delta=%d", before, after, int64(after)-int64(before))
	runtime.KeepAlive(s)
}

func TestBoundsAllOwnerTables(t *testing.T) {
	s := New()
	before := boundsHeap()
	var owners [MaxOwners]*Owner
	var raw [MaxRanges]ranges.Range
	for i := range raw {
		raw[i] = ranges.Range{Start: uint32(i * 2), Length: 1, SourceID: ranges.SourceID(i)}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, MaxRanges, raw[:], 128).Valid)
	for i := range owners {
		o := s.Acquire()
		owners[i] = o
		require.False(t, o.Disabled())
		for j := 0; j < MaxBindings; j++ {
			object := new(int)
			*object = j
			kind := BindingURL
			if j < MaxReaderBindings {
				kind = BindingReader
			}
			require.True(t, BindObject(o, object, kind))
		}
		require.False(t, BindObject(o, new(int), BindingURL))
		require.False(t, BindObject(o, new(int), BindingReader))
		for j := 0; j < MaxWriters; j++ {
			data := make([]byte, 128)
			view := WriterView{Pointer: uintptr(unsafe.Pointer(unsafe.SliceData(data))), Length: 128, Capacity: 128}
			require.True(t, o.UpdateWriter(&data, WriterStringBuilder, WriterView{Capacity: 128}, view, &set, 128, 128))
		}
		require.False(t, o.UpdateWriter(new(int), WriterStringBuilder, WriterView{}, WriterView{Pointer: 1, Length: 128, Capacity: 128}, &set, 128, 128))
		// Re-adoption replaces one key but consumes the fixed root-record cap.
		// This drives all 32,768 root records without exceeding 16,384 values.
		data := make([]byte, 128)
		for j := 0; j < MaxRootsPerOwner; j++ {
			_, ok := o.AdoptBytes(data, &set)
			require.True(t, ok)
		}
		_, ok := o.AdoptBytes(data, &set)
		require.False(t, ok)
	}
	require.True(t, s.Acquire().Disabled())
	require.Zero(t, s.Stats().OverflowFree)
	after := boundsHeap()
	t.Logf("full tables owners=%d roots=%d bindings=%d readers=%d writers=%d overflowFree=%d charged=%d values=%d heapBefore=%d heapAfter=%d delta=%d",
		MaxOwners, MaxOwners*MaxRootsPerOwner, MaxOwners*MaxBindings, MaxOwners*MaxReaderBindings,
		s.writerStates.Load(), s.Stats().OverflowFree, s.ProcessCharged(), s.ProcessValues(), before, after, int64(after)-int64(before))
	for _, o := range owners {
		o.Finish()
	}
	require.Zero(t, s.ProcessCharged())
	require.Zero(t, s.ProcessValues())
	require.Zero(t, s.writerStates.Load())
	require.Equal(t, uint16(OverflowBlocks), s.Stats().OverflowFree)
	t.Logf("finished heap=%d charged=%d values=%d overflowFree=%d", boundsHeap(), s.ProcessCharged(), s.ProcessValues(), s.Stats().OverflowFree)
	runtime.KeepAlive(s)
}

func TestBoundsOverflowRanges(t *testing.T) {
	s := New()
	o := s.Acquire()
	var raw [MaxRanges]ranges.Range
	for i := range raw {
		raw[i] = ranges.Range{Start: uint32(i * 2), Length: 1, SourceID: ranges.SourceID(i)}
	}
	var set ranges.Set
	require.True(t, ranges.AdoptCanonical(&set, MaxRanges, raw[:], 128).Valid)
	for i := 0; i <= OverflowBlocks; i++ {
		data := make([]byte, 128)
		_, ok := o.AdoptBytes(data, &set)
		require.True(t, ok)
		key, _ := BytesKey(data)
		var snapshot Snapshot
		require.True(t, s.Lookup(key, &snapshot))
		entry, ok := snapshot.At(0)
		require.True(t, ok)
		want := MaxRanges
		if i == OverflowBlocks {
			want = GuaranteedRanges
		}
		require.Equal(t, want, entry.Ranges.Len())
	}
	t.Logf("overflow roots=%d fullRangeRoots=%d excessRootRanges=%d free=%d rangeDrops=%d",
		OverflowBlocks+1, OverflowBlocks, GuaranteedRanges, s.Stats().OverflowFree, o.Counters().Ranges)
	o.Finish()
	require.Equal(t, uint16(OverflowBlocks), s.Stats().OverflowFree)
}
