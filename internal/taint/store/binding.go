// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"reflect"
	"slices"
	"sync"
	"unsafe"
)

const (
	MaxBindings       = 256
	MaxReaderBindings = 8
	bindingIndexSlots = 512

	// MaxReaderInputs is the maximum number of inputs of a derived exclusive
	// reader binding (plan encoding-json-v2, section 6.5, rule (e)). It is
	// the io.MultiReader limit of 8 inputs.
	MaxReaderInputs = 8
	// maxInputChecks is the maximum number of input lookups that one reader
	// lookup does to revalidate derived exclusive bindings (rule (e)). This
	// limit also limits the recursion depth. When a revalidation needs more
	// lookups, the binding is not effectively exclusive.
	maxInputChecks = 16
	// readerBindSlots is the number of reader bind counters of a store
	// (rule (f), Store.readerBinds). Two objects can use the same counter.
	// Then a bind of one object by another owner also removes the
	// exclusivity of the bindings of the other object: a safe miss. 4,096
	// counters use 32 KiB.
	readerBindSlots = 4096
	// noReaderSlot is the counter slot of a bind that is not a reader bind.
	noReaderSlot = -1
)

// An entry index of the binding table must fit in a uint8 (the input entries
// of rule (e), OwnerRef.entry).
const _ = uint8(MaxBindings - 1)

// BindingKind identifies a supported typed object relationship.
type BindingKind uint8

const (
	BindingInvalid BindingKind = iota
	BindingURL
	BindingReader
)

type binding struct {
	// Bindings retain typed objects outside the managed-root byte charge.
	// The table and reader count are bounded, but reader graphs can retain
	// uncharged payload data. This trade-off preserves reader propagation.
	object  any // strong typed pointer
	pointer uintptr
	kind    BindingKind
	// exclusive is true only for a reader binding with a proof that every
	// byte of the reader comes from data of this owner (plan
	// encoding-json-v2, section 6.5, rule (a)).
	exclusive bool
	// viaGuard is true when the proof of exclusive depends on a per-Read
	// guard (plan encoding-json-v2, section 6.6). The owner retargeted bit
	// then removes the effective exclusivity (rule (a2)).
	viaGuard bool
	// inputs is 0 for a binding with no input (a root binding, or a binding
	// that is not exclusive). Else it is the index + 1 of the input set of
	// an exclusive derived binding in bindingTable.inputs (rule (e)).
	inputs uint8
	// demoted is true when the entry was a reader binding and then changed
	// to another kind. A demoted entry never becomes exclusive again in this
	// owner generation, thus one entry has at most one exclusive reader
	// binding (rule (f)). A ReaderToken and an input set can then identify
	// the binding by its entry index.
	demoted bool
}

// readerInputs is the input set of a derived exclusive reader binding (plan
// encoding-json-v2, section 6.5, rule (e)). Each item is the index of an input
// binding in the entries of the same table. Entries do not move while the
// owner generation is live, thus an index stays valid until reset. The set
// has no counter stamp: each input is a reader binding of the same table,
// with its own creation baseline (rule (f), bindingTable.readerExpect), and a
// lookup of the derived binding does a complete lookup of each input.
type readerInputs struct {
	entries [MaxReaderInputs]uint8
	count   uint8
}

type bindingTable struct {
	mu          sync.RWMutex
	entries     [MaxBindings]binding
	index       [bindingIndexSlots]uint16 // entry index + 1
	count       uint16
	readerCount uint8
	// readers holds the entry indexes of the reader bindings (readerCount
	// items), so that stampReaderBind finds them without a scan of entries.
	readers [MaxReaderBindings]uint8
	// readerExpect holds, for each item of readers, the value that the
	// reader bind counter of the binding has when no other owner did a
	// reader bind with this counter since the binding was made (rule (f),
	// the creation baseline). The bind that makes the reader binding sets
	// it to the value of its own counter add. Each later reader bind of
	// this owner with the same counter adds 1 to it, under the table lock
	// (stampReaderBind). A lookup reads it and the counter under the table
	// read lock (lookupObject).
	readerExpect [MaxReaderBindings]uint64
	// inputs holds the input sets of rule (e). An input set is never
	// released before reset. When all the sets are used, a new derived
	// binding is not exclusive.
	inputs     [MaxReaderBindings]readerInputs
	inputsUsed uint8
}

// OwnerRef is a compact generation-captured binding result.
type OwnerRef struct {
	store      *Store
	generation uint64
	index      uint8
	Kind       BindingKind
	// Exclusive is the effective exclusive flag of a reader binding (plan
	// encoding-json-v2, section 6.5, rule (a2)). It is true only when the
	// binding is exclusive, no other owner did a reader bind with its
	// counter since the binding was made (rule (f)), if it depends on a Read
	// guard, the owner is not retargeted, and, if it is a derived binding,
	// each of its inputs is still effectively exclusive to the same owner
	// (rule (e)). Only LookupReaderValue computes it. Other lookups set it
	// to false.
	Exclusive bool
	// ViaGuard reports whether the binding depends on a Read guard.
	ViaGuard bool
	// entry is the index of the binding in the table of the owner. Only
	// BindDerivedReaderValue uses it, after it checks the identity again.
	entry uint8
}

// Handle returns a revalidated owner handle by value, without allocation.
func (r OwnerRef) Handle() (Owner, bool) {
	if r.store == nil || r.index >= MaxOwners {
		return Owner{}, false
	}
	record := &r.store.owners[r.index]
	if record.generation.Load() != r.generation || ownerState(record.state.Load()) != stateActive {
		return Owner{}, false
	}
	return Owner{store: r.store, owner: record, index: r.index, gen: r.generation}, true
}

// Identity returns the active store-owner slot identity captured by this ref.
func (r OwnerRef) Identity() (index uint8, generation, ownerID uint64, ok bool) {
	owner, ok := r.Handle()
	if !ok {
		return 0, 0, 0, false
	}
	return r.index, r.generation, owner.ID(), true
}

// ReaderToken is the exclusive owner of a reader at one reader lookup (plan
// encoding-json-v2, section 6.5, rule (f)). A consumer takes a token BEFORE
// the first byte of the reader flows, and calls Revalidate with the ref of a
// new complete lookup AFTER the bytes flowed, at attribution time.
//
// The token identifies one exclusive reader binding: the owner slot, the
// owner generation, and the entry of the binding. In one generation, an entry
// has at most one exclusive reader binding (binding.demoted), and its
// exclusive flag never comes back after a loss. Thus when Revalidate accepts
// a ref, the same binding was exclusive from the capture to the new lookup.
// The effective exclusivity of the new lookup includes the creation baseline
// of rule (f): no other owner did a reader bind with the counter of the
// reader since the binding was made. Thus a bind of another owner that
// started and ended before the new lookup gives a miss, also when it ended
// before the capture.
//
// The fields are exported only so that the request package can copy a token
// to and from iobridge.ReadToken. Make a token only with OwnerRef.ReaderToken.
type ReaderToken struct {
	Store      *Store
	Generation uint64
	Index      uint8
	Entry      uint8
	OK         bool
}

// ReaderToken returns the token of r. The token is OK only when r is an
// effectively exclusive reader binding of an active owner. The caller must
// also check that the lookup of r was complete and found exactly one owner.
func (r OwnerRef) ReaderToken() ReaderToken {
	if !r.Exclusive || r.Kind != BindingReader {
		return ReaderToken{}
	}
	if _, ok := r.Handle(); !ok {
		return ReaderToken{}
	}
	return ReaderToken{Store: r.store, Generation: r.generation, Index: r.index, Entry: r.entry, OK: true}
}

// Revalidate reports whether r, the only ref of a complete reader lookup
// (LookupReaderValue) of the same reader, keeps the exclusive owner of t
// (rule (f)). It is true only when t is OK, r is effectively exclusive (with
// the checks of rules (a2), (e), and (f) at the lookup of r), r refers to the
// same owner generation and the same binding entry, and the owner is active.
// The caller must check that the lookup of r was complete and found exactly
// one owner.
func (t ReaderToken) Revalidate(r OwnerRef) bool {
	if !t.OK || !r.Exclusive || r.Kind != BindingReader || r.store != t.Store ||
		r.index != t.Index || r.generation != t.Generation || r.entry != t.Entry {
		return false
	}
	_, ok := r.Handle()
	return ok
}

// BindObject strongly binds a typed heap object to owner. It never derives a
// pointer from an interface data word.
func BindObject[T any](owner *Owner, object *T, kind BindingKind) bool {
	if owner == nil || object == nil || unsafe.Sizeof(*object) == 0 || kind == BindingInvalid {
		return false
	}
	pointer := uintptr(unsafe.Pointer(object))
	slot := readerSlotOf(kind, pointer, typeWord(object))
	if !owner.beginWrite() {
		owner.addReaderBind(slot)
		return false
	}
	defer owner.endWrite()
	table := &owner.owner.bindings
	if !table.mu.TryLock() {
		owner.owner.drops.contention.Add(1)
		owner.addReaderBind(slot)
		return false
	}
	defer table.mu.Unlock() // +checklocksforce: TryLock.
	// Add to the counter BEFORE the table change (rule (f)).
	counter := owner.addReaderBind(slot)
	bound := table.bind(owner, object, pointer, kind, false, false, nil, counter)
	table.stampReaderBind(slot)
	return bound
}

// BindObjectValue strongly binds a non-nil dynamic pointer to owner. The
// original interface is retained as the typed anchor; its data word is never
// inspected directly and the numeric pointer is only a comparison key. The
// identity of a binding is the dynamic type and the address of object. One
// identity can have one binding kind; rebinding replaces its prior kind. A
// reader binding made by this function is not exclusive.
func BindObjectValue(owner *Owner, object any, kind BindingKind) bool {
	return bindValue(owner, object, kind, false, false)
}

// BindReaderValue strongly binds a non-nil dynamic pointer reader to owner.
// exclusive tells that the caller asserts that every byte of object comes
// from data of owner, with no condition on other readers (a root binding: the
// request body at entry, request.BindReader). Use BindDerivedReaderValue for
// an exclusive binding that depends on input readers. viaGuard tells that the
// proof depends on a per-Read guard. A rebind of the same identity keeps
// exclusive only when the old and the new binding are both exclusive, and
// keeps viaGuard when one of them has it.
func BindReaderValue(owner *Owner, object any, exclusive, viaGuard bool) bool {
	return bindValue(owner, object, BindingReader, exclusive, viaGuard)
}

func bindValue(owner *Owner, object any, kind BindingKind, exclusive, viaGuard bool) bool {
	pointer, ok := dynamicPointer(object)
	if !ok || owner == nil || kind == BindingInvalid {
		return false
	}
	slot := readerSlotOf(kind, pointer, typeWord(object))
	if !owner.beginWrite() {
		owner.addReaderBind(slot)
		return false
	}
	defer owner.endWrite()
	table := &owner.owner.bindings
	if !table.mu.TryLock() {
		owner.owner.drops.contention.Add(1)
		owner.addReaderBind(slot)
		return false
	}
	defer table.mu.Unlock() // +checklocksforce: TryLock.
	// Add to the counter BEFORE the table change (rule (f)).
	counter := owner.addReaderBind(slot)
	runHook(hookReaderBind, 0)
	bound := table.bind(owner, object, pointer, kind, exclusive, viaGuard, nil, counter)
	table.stampReaderBind(slot)
	return bound
}

// BindDerivedReaderValue binds the reader object exclusively to owner, with a
// proof that depends on its input readers (plan encoding-json-v2, section 6.5,
// rule (e)). For each i, refs[i] must be the only ref that a complete lookup
// (LookupReaderValue) of inputs[i] found, it must refer to owner, and it must
// be effectively exclusive. The binding records the input entries. A later
// lookup of object reports it as exclusive only when each input is still
// effectively exclusive to the same owner. The exclusivity of an input
// includes its creation baseline (rule (f)), thus a reader bind of an input
// by another owner after the proof gives a miss, also after that owner ends.
//
// It returns false and makes no binding when inputs is empty or has more
// than MaxReaderInputs items, when a ref does not refer to owner, or when the
// entry of a ref is not the reader binding of its input any more. A rebind
// of the same identity keeps exclusive only when the old binding is
// exclusive too, and then the binding keeps the inputs of both. When the
// table has no free input set, or the two input sets together have more than
// MaxReaderInputs items, the binding is made but it is not exclusive.
func BindDerivedReaderValue(owner *Owner, object any, viaGuard bool, inputs []any, refs []OwnerRef) bool {
	if len(inputs) == 0 || len(inputs) > MaxReaderInputs || len(refs) != len(inputs) {
		return false
	}
	pointer, ok := dynamicPointer(object)
	if !ok || owner == nil {
		return false
	}
	slot := readerSlotOf(BindingReader, pointer, typeWord(object))
	if !owner.beginWrite() {
		owner.addReaderBind(slot)
		return false
	}
	defer owner.endWrite()
	table := &owner.owner.bindings
	if !table.mu.TryLock() {
		owner.owner.drops.contention.Add(1)
		owner.addReaderBind(slot)
		return false
	}
	defer table.mu.Unlock() // +checklocksforce: TryLock.
	// Add to the counter BEFORE the table change (rule (f)).
	counter := owner.addReaderBind(slot)
	defer table.stampReaderBind(slot)
	var proofs [MaxReaderInputs]uint8
	count := 0
	for i := range refs {
		ref := &refs[i]
		if ref.store != owner.store || ref.index != owner.index || ref.generation != owner.gen || !ref.Exclusive {
			return false
		}
		inputPointer, ok := dynamicPointer(inputs[i])
		if !ok || uint16(ref.entry) >= table.count {
			return false
		}
		input := &table.entries[ref.entry]
		if input.kind != BindingReader || input.pointer != inputPointer || typeWord(input.object) != typeWord(inputs[i]) {
			return false
		}
		if !slices.Contains(proofs[:count], ref.entry) {
			proofs[count] = ref.entry
			count++
		}
	}
	return table.bind(owner, object, pointer, BindingReader, true, viaGuard, proofs[:count], counter)
}

// LookupObject returns active owners bound to object. out bounds owner fanout;
// extra owners are dropped with telemetry. It does not compute
// OwnerRef.Exclusive (it is always false): use LookupReaderValue.
func LookupObject[T any](store *Store, object *T, out []OwnerRef) int {
	if store == nil || object == nil || len(out) == 0 {
		return 0
	}
	count, _ := lookupObject(store, uintptr(unsafe.Pointer(object)), typeWord(object), BindingInvalid, out, nil)
	return count
}

// LookupObjectValue returns active owners bound to a non-nil dynamic pointer of
// kind. Non-pointer and typed-nil interface values are safe misses. It does
// not compute OwnerRef.Exclusive (it is always false): use LookupReaderValue.
func LookupObjectValue(store *Store, object any, kind BindingKind, out []OwnerRef) int {
	pointer, ok := dynamicPointer(object)
	if !ok || kind == BindingInvalid || store == nil || len(out) == 0 {
		return 0
	}
	count, _ := lookupObject(store, pointer, typeWord(object), kind, out, nil)
	return count
}

// LookupReaderValue returns the active owners with a reader binding of a
// non-nil dynamic pointer, and reports whether the lookup is complete. A
// lookup is not complete when it skipped an active owner because of lock
// contention, or when out cannot hold all the owners that it found. An
// incomplete result is unknown: it must not prove attribution or exclusivity
// (plan encoding-json-v2, section 6.5, rule (b)). A non-pointer or typed-nil
// value has no binding, thus its lookup is complete with no owner.
//
// OwnerRef.Exclusive is the effective exclusivity (rules (a2), (e), and (f)):
// no other owner did a reader bind with the counter of object since the
// binding was made, and, for a derived binding, each of its inputs is
// revalidated. A revalidation that fails or that needs more than
// maxInputChecks input lookups gives Exclusive = false.
func LookupReaderValue(store *Store, object any, out []OwnerRef) (int, bool) {
	pointer, ok := dynamicPointer(object)
	if !ok || store == nil {
		return 0, true
	}
	if len(out) == 0 {
		return 0, false
	}
	budget := maxInputChecks
	return lookupObject(store, pointer, typeWord(object), BindingReader, out, &budget)
}

// readerSlotOf returns the reader bind counter slot of the identity (pointer,
// typ) for a bind of kind, or noReaderSlot when kind is not BindingReader.
func readerSlotOf(kind BindingKind, pointer, typ uintptr) int {
	if kind != BindingReader {
		return noReaderSlot
	}
	return readerBindSlot(pointer, typ)
}

// readerBindSlot returns the reader bind counter slot of the identity
// (pointer, typ).
func readerBindSlot(pointer, typ uintptr) int {
	return bindingHash(pointer^typ*0x9e3779b9) & (readerBindSlots - 1)
}

// addReaderBind adds 1 to the reader bind counter slot of the store of o, for
// a reader bind attempt (rule (f)), and returns the new value. It does nothing
// and returns 0 for noReaderSlot.
//
// Ordering: a bind that changes the table of o calls addReaderBind under the
// table lock, BEFORE the change, and calls stampReaderBind after the change,
// before the unlock. A bind that cannot lock the table, or that fails before,
// calls addReaderBind with no stamp: no lookup can see its binding, thus it
// must remove the exclusivity of the bindings with this counter.
func (o *Owner) addReaderBind(slot int) uint64 {
	if slot == noReaderSlot || o.store == nil {
		return 0
	}
	return o.store.readerBinds[slot].Add(1)
}

// MarkRetargeted sets the sticky retargeted bit of the owner in slot index,
// only if the slot still has generation. The bit removes the effective
// exclusivity of all the guarded reader bindings of this owner (plan
// encoding-json-v2, section 6.5, rule (a2)). It takes no lock.
func MarkRetargeted(store *Store, index uint8, generation uint64) {
	if store == nil || index >= MaxOwners || generation == 0 {
		return
	}
	record := &store.owners[index]
	if record.generation.Load() == generation {
		record.retargeted.Store(true)
		record.drops.retargets.Add(1)
	}
}

// inputKey is the identity of an input binding, copied under the table lock.
type inputKey struct {
	pointer uintptr
	typ     uintptr
}

// lookupObject finds the owners with a binding of the identity (pointer,
// typ). When budget is nil, it does not compute OwnerRef.Exclusive. Else it
// computes the effective exclusivity, and each revalidation of an input of
// rule (e) uses one unit of budget.
func lookupObject(store *Store, pointer, typ uintptr, requiredKind BindingKind, out []OwnerRef, budget *int) (int, bool) {
	count := 0
	complete := true
	slot := noReaderSlot
	if budget != nil {
		slot = readerBindSlot(pointer, typ)
	}
	for i := range store.owners {
		record := &store.owners[i]
		if ownerState(record.state.Load()) != stateActive {
			continue
		}
		if slot != noReaderSlot {
			runHook(hookLookupOwner, i)
		}
		if !record.lifecycleMu.TryRLock() {
			complete = false
			continue
		}
		generation := record.generation.Load()
		if ownerState(record.state.Load()) != stateActive {
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
			continue
		}
		table := &record.bindings
		if !table.mu.TryRLock() {
			record.drops.contention.Add(1)
			record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock. // +checklocksforce: TryRLock.
			complete = false
			continue
		}
		position, found := table.find(pointer, typ)
		var entry binding
		if found {
			entry = table.entries[position]
			found = requiredKind == BindingInvalid || entry.kind == requiredKind
		}
		exclusive := found && slot != noReaderSlot && entry.kind == BindingReader && entry.exclusive
		if exclusive {
			// Rule (f): read the counter UNDER the table read lock. A
			// reader bind of this owner holds the table lock from its
			// counter add to its stamp, thus the counter and the baseline
			// are a consistent pair. Every other add only makes the
			// counter larger than the baseline.
			exclusive = table.unchanged(uint8(position), store.readerBinds[slot].Load())
		}
		// Copy the identities of the inputs of rule (e) under the lock.
		var keys [MaxReaderInputs]inputKey
		inputs := 0
		if exclusive && entry.inputs != 0 {
			set := &table.inputs[entry.inputs-1]
			for _, input := range set.entries[:set.count] {
				keys[inputs] = inputKey{pointer: table.entries[input].pointer, typ: typeWord(table.entries[input].object)}
				inputs++
			}
		}
		retargeted := record.retargeted.Load()
		table.mu.RUnlock()           // +checklocksforce: TryRLock.
		record.lifecycleMu.RUnlock() // +checklocksforce: TryRLock.
		if inputs != 0 {
			runHook(hookInputCounters, 0)
		}
		if !found {
			continue
		}
		if count >= len(out) {
			record.drops.fanout.Add(1)
			complete = false
			continue
		}
		exclusive = exclusive && !(entry.viaGuard && retargeted)
		if exclusive && inputs != 0 {
			exclusive = inputsExclusive(store, uint8(i), generation, keys[:inputs], budget)
		}
		out[count] = OwnerRef{
			store: store, index: uint8(i), generation: generation, Kind: entry.kind,
			Exclusive: exclusive, ViaGuard: entry.viaGuard, entry: uint8(position),
		}
		count++
	}
	return count, complete
}

// inputsExclusive reports whether a complete lookup of each input finds
// exactly the owner (index, generation), with an effectively exclusive
// binding (rule (e)). Each input lookup uses one unit of budget. It returns
// false when the budget is used up.
func inputsExclusive(store *Store, index uint8, generation uint64, keys []inputKey, budget *int) bool {
	for _, key := range keys {
		if *budget <= 0 {
			return false
		}
		*budget--
		// Two refs, so that a second owner is a count of 2 and not a
		// fanout drop.
		var refs [2]OwnerRef
		count, complete := lookupObject(store, key.pointer, key.typ, BindingReader, refs[:], budget)
		if !complete || count != 1 || refs[0].index != index || refs[0].generation != generation || !refs[0].Exclusive {
			return false
		}
	}
	return true
}

// bind adds or changes the binding of object. counter is the value that the
// reader bind counter add of this bind returned (addReaderBind). A new reader
// binding gets it as its creation baseline (rule (f)).
func (t *bindingTable) bind(owner *Owner, object any, pointer uintptr, kind BindingKind, exclusive, viaGuard bool, inputs []uint8, counter uint64) bool {
	typ := typeWord(object)
	if kind != BindingReader {
		exclusive, viaGuard, inputs = false, false, nil
	}
	start := bindingHash(pointer) & (bindingIndexSlots - 1)
	for probe := 0; probe < bindingIndexSlots; probe++ {
		slot := (start + probe) & (bindingIndexSlots - 1)
		encoded := t.index[slot]
		if encoded == 0 {
			if t.count >= MaxBindings || kind == BindingReader && t.readerCount >= MaxReaderBindings {
				owner.owner.drops.full.Add(1)
				return false
			}
			entry := t.count
			t.entries[entry] = binding{object: object, pointer: pointer, kind: kind, viaGuard: viaGuard}
			t.setInputs(owner, &t.entries[entry], exclusive, inputs)
			t.index[slot] = entry + 1
			t.count++
			if kind == BindingReader {
				t.addReader(uint8(entry), counter)
			}
			return true
		}
		entry := &t.entries[encoded-1]
		// Two objects of different types can have the same address, for
		// example a struct and its first field. They are different
		// bindings (plan encoding-json-v2, section 6.5, rule (d)).
		if entry.pointer == pointer && typeWord(entry.object) == typ {
			switch {
			case entry.kind != BindingReader && kind == BindingReader:
				if t.readerCount >= MaxReaderBindings {
					owner.owner.drops.full.Add(1)
					return false
				}
				t.addReader(uint8(encoded-1), counter)
				// The binding gets the new proof only. It keeps the
				// input set of an earlier reader proof for reuse. A
				// demoted entry is never exclusive again (rule (f)).
				if entry.inputs != 0 {
					t.inputs[entry.inputs-1] = readerInputs{}
				}
				exclusive = exclusive && !entry.demoted
			case entry.kind == BindingReader && kind != BindingReader:
				t.removeReader(uint8(encoded - 1))
				entry.demoted = true
			case entry.kind == BindingReader:
				// A rebind cannot remove the bytes that the reader
				// can produce from its other sources. Thus the new
				// binding is exclusive only when both proofs hold, and
				// then it depends on the inputs of both.
				exclusive = exclusive && entry.exclusive
				viaGuard = viaGuard || entry.viaGuard
				if exclusive && entry.inputs != 0 {
					exclusive = t.inputs[entry.inputs-1].add(inputs)
					inputs = nil
				}
			}
			entry.object = object
			entry.kind = kind
			entry.viaGuard = viaGuard
			t.setInputs(owner, entry, exclusive, inputs)
			return true
		}
	}
	owner.owner.drops.full.Add(1)
	return false
}

// add adds inputs to the set. An input that the set has already is not
// added again. It returns false when the result has more than
// MaxReaderInputs items; the set is then not valid.
func (set *readerInputs) add(inputs []uint8) bool {
	for _, input := range inputs {
		if slices.Contains(set.entries[:set.count], input) {
			continue
		}
		if set.count == MaxReaderInputs {
			return false
		}
		set.entries[set.count] = input
		set.count++
	}
	return true
}

// addReader adds the entry index position to t.readers, with the creation
// baseline of rule (f). counter is the value of the counter add of this bind.
// stampReaderBind adds the 1 of this bind after the table change, thus the
// baseline is counter - 1 here. The caller must check that t.readers has a
// free item. The table lock must be held.
func (t *bindingTable) addReader(position uint8, counter uint64) {
	t.readers[t.readerCount] = position
	t.readerExpect[t.readerCount] = counter - 1
	t.readerCount++
}

// removeReader removes the entry index position from t.readers. The table
// lock must be held.
func (t *bindingTable) removeReader(position uint8) {
	for i := range t.readers[:t.readerCount] {
		if t.readers[i] == position {
			t.readerCount--
			t.readers[i] = t.readers[t.readerCount]
			t.readerExpect[i] = t.readerExpect[t.readerCount]
			t.readers[t.readerCount] = 0
			t.readerExpect[t.readerCount] = 0
			return
		}
	}
}

// unchanged reports whether the reader binding at the entry index position
// has its creation baseline equal to counter, the current value of its reader
// bind counter (rule (f)). The table lock must be held (a read lock is
// sufficient), and counter must be read under it.
func (t *bindingTable) unchanged(position uint8, counter uint64) bool {
	for i := range t.readers[:t.readerCount] {
		if t.readers[i] == position {
			return t.readerExpect[i] == counter
		}
	}
	return false
}

// stampReaderBind adds 1 to the creation baseline of each reader binding of
// t with the reader bind counter slot, for a reader bind of the owner of t
// that added 1 to that counter (rule (f), addReaderBind). Thus a bind of the
// owner itself does not remove the exclusivity of its own readers. Call it
// after the table change, so that a reader binding that the bind makes gets
// the add too. It does nothing for noReaderSlot. The table lock must be held,
// from before the counter add until after this call: a lookup of this owner
// reads the baselines and the counter under the read lock, thus it sees both
// changes or none. The cost is at most MaxReaderBindings hash computations.
func (t *bindingTable) stampReaderBind(slot int) {
	if slot == noReaderSlot {
		return
	}
	for i, position := range t.readers[:t.readerCount] {
		entry := &t.entries[position]
		if readerBindSlot(entry.pointer, typeWord(entry.object)) == slot {
			t.readerExpect[i]++
		}
	}
}

// setInputs sets the exclusive flag of entry, and gives it the input set
// inputs. When inputs is empty, the input set of entry does not change. A
// derived exclusive binding that gets no free input set is not exclusive. A
// binding that is not exclusive keeps its input set, but no lookup reads it.
// The table lock must be held.
func (t *bindingTable) setInputs(owner *Owner, entry *binding, exclusive bool, inputs []uint8) {
	entry.exclusive = exclusive
	if !exclusive || len(inputs) == 0 {
		return
	}
	if entry.inputs == 0 {
		if t.inputsUsed >= MaxReaderBindings {
			owner.owner.drops.full.Add(1)
			entry.exclusive = false
			return
		}
		t.inputsUsed++
		entry.inputs = t.inputsUsed
	}
	set := &t.inputs[entry.inputs-1]
	*set = readerInputs{}
	set.add(inputs)
}

func dynamicPointer(object any) (uintptr, bool) {
	if object == nil {
		return 0, false
	}
	value := reflect.ValueOf(object)
	if value.Kind() != reflect.Pointer || value.IsNil() || value.Type().Elem().Size() == 0 {
		return 0, false
	}
	pointer := value.Pointer()
	return pointer, pointer != 0
}

// eface is the layout of an empty interface value.
type eface struct {
	typ  unsafe.Pointer
	data unsafe.Pointer
}

// typeWord returns the dynamic type word of object as a comparison key. It
// does not allocate, and it never converts the result back to a pointer.
func typeWord(object any) uintptr {
	return uintptr((*eface)(unsafe.Pointer(&object)).typ)
}

// find returns the entry index of the binding of the identity (pointer, typ).
func (t *bindingTable) find(pointer, typ uintptr) (int, bool) {
	start := bindingHash(pointer) & (bindingIndexSlots - 1)
	for probe := 0; probe < bindingIndexSlots; probe++ {
		encoded := t.index[(start+probe)&(bindingIndexSlots-1)]
		if encoded == 0 {
			return 0, false
		}
		entry := &t.entries[encoded-1]
		if entry.pointer == pointer && typeWord(entry.object) == typ {
			return int(encoded - 1), true
		}
	}
	return 0, false
}

func (t *bindingTable) reset() {
	t.mu.Lock()
	clear(t.entries[:])
	clear(t.index[:])
	clear(t.inputs[:])
	clear(t.readers[:])
	clear(t.readerExpect[:])
	t.count = 0
	t.readerCount = 0
	t.inputsUsed = 0
	t.mu.Unlock()
}

func bindingHash(pointer uintptr) int {
	hash := uint64(pointer)
	hash ^= hash >> 30
	hash *= 0xbf58476d1ce4e5b9
	hash ^= hash >> 27
	return int(hash)
}
