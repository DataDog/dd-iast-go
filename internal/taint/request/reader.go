// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import (
	"context"
	"sync/atomic"

	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/iobridge"
	"github.com/DataDog/dd-iast-go/internal/taint/jsonbridge"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

// incompleteLookupForTest makes each reader lookup incomplete. Only tests set
// it, to check that an incomplete lookup is a miss (rule (b)). It is a flag and
// not a function variable: an indirect call would move the lookup result
// arrays of the callers to the heap.
var incompleteLookupForTest atomic.Bool

// lookupReader returns the active request owners with a reader binding of
// object, and reports whether the lookup is complete. When no request is
// active, it returns at once with a complete empty result.
func lookupReader(object any, out []store.OwnerRef) (int, bool) {
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 {
		return 0, true
	}
	count, complete := store.LookupReaderValue(manager.store, object, out)
	if incompleteLookupForTest.Load() {
		complete = false
	}
	// Fail closed when a retarget callback failed (iobridge.RetargetLost):
	// the retargeted bit of an owner can be missing, thus no binding that
	// depends on a Read guard is effectively exclusive (rule (a2)). Each
	// binding over a guarded binding has ViaGuard too.
	if iobridge.RetargetLost() {
		for i := range out[:count] {
			if out[i].ViaGuard {
				out[i].Exclusive = false
			}
		}
	}
	return count, complete
}

// SetIncompleteReaderLookupsForTest makes each reader lookup incomplete until
// restore is called. Only tests call it.
func SetIncompleteReaderLookupsForTest() (restore func()) {
	incompleteLookupForTest.Store(true)
	return func() { incompleteLookupForTest.Store(false) }
}

// BindReader binds a non-nil pointer reader by address to the active context
// owner. The caller asserts that every byte of reader comes from data of this
// request, thus the binding is exclusive. Non-pointer and zero-sized values
// are safe misses.
//
// Contract (assumption (A2) of the reader binding rules in the
// internal/taint/store package doc): the assertion applies to all the bytes
// that reader gives while it is bound, not only to the bytes that it holds now.
// Thus do not bind a reader that code can reset to other data (for example a
// *strings.Reader, a *bytes.Reader, or a *bytes.Buffer that is used again)
// while the request is active. A reset keeps the address and the bind counter
// of the reader. Thus no lookup and no token revalidation can find it, and a
// consumer that took its token before the reset attributes the new bytes to
// this request.
func BindReader(ctx context.Context, reader any) bool {
	analysis, ok := FromContext(ctx).Analysis()
	if !ok {
		return false
	}
	owner := analysis.storeOwner()
	return owner != nil && store.BindReaderValue(owner, reader, true, false)
}

// PropagateReader binds output to every active owner bound to input. Use it
// only for a wrapper with one input that user code cannot retarget (for
// example io.TeeReader and http.MaxBytesReader). The binding is exclusive only
// when a complete lookup finds exactly one owner of input, with an effectively
// exclusive binding. Dynamic non-pointer reader values are unsupported safe
// misses.
func PropagateReader(input, output any) {
	propagateReader(input, output, true)
}

// PropagateSharedReader binds output to every active owner bound to input,
// with a binding that is never exclusive. The manual helper
// iast/bufio.Propagate uses it, because an unwoven bufio has no Read guard.
func PropagateSharedReader(input, output any) {
	propagateReader(input, output, false)
}

// Invariant of the derived exclusive bindings (reader binding rule (e) in the
// internal/taint/store package doc): a wrapper binding is exclusive only with a
// proof from its inputs, and it records these inputs
// (store.BindDerivedReaderValue). Each reader lookup revalidates the inputs.
// Thus when an input gets a second owner, or stops being effectively exclusive,
// each wrapper over it stops being exclusive too, before the next attribution.
// The loss is sticky: the store counts the reader binds of each reader, and a
// reader binding is effectively exclusive only when no other owner did a reader
// bind with its counter since the binding was made (rule (f)). Thus a wrapper
// stays not exclusive also after the second owner ends.

func propagateReader(input, output any, allow bool) {
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count, complete := lookupReader(input, refs[:])
	if allow && complete && count == 1 && refs[0].Exclusive {
		if owner, ok := refs[0].Handle(); ok &&
			store.BindDerivedReaderValue(&owner, output, refs[0].ViaGuard, []any{input}, refs[:1]) {
			return
		}
	}
	bindReaderOwners(refs[:count], output)
}

// bindReaderOwners binds output to each owner of refs, with a binding that is
// not exclusive.
func bindReaderOwners(refs []store.OwnerRef, output any) {
	for i := range refs {
		owner, ok := refs[i].Handle()
		if !ok {
			continue
		}
		store.BindReaderValue(&owner, output, false, false)
	}
}

// joinHookForTest runs after the input lookups of PropagateJoinedReader and
// before its bind. Only tests set it.
var joinHookForTest atomic.Pointer[func()]

// PropagateJoinedReader binds output, a reader that reads from more than one
// input (io.MultiReader), to the owners of its inputs. inputs holds the first
// min(count, iobridge.MaxJoinInputs) inputs, and count is the number of
// inputs of output. The binding is exclusive only when count is 1 to
// iobridge.MaxJoinInputs, a complete lookup of each input finds the same one
// owner, with an effectively exclusive binding, and one bind records all the
// inputs (rule (e)). Thus a change of an input after the lookups (a second
// owner, or the end of the owner) makes the binding not exclusive. In all
// other cases, output gets a binding that is not exclusive to each owner of
// the inputs in inputs.
func PropagateJoinedReader(inputs [iobridge.MaxJoinInputs]any, count int, output any) {
	manager := processManager.Load()
	if manager == nil || manager.used.Load() == 0 || count <= 0 {
		return
	}
	known := min(count, len(inputs))
	if count <= len(inputs) {
		var proofs [iobridge.MaxJoinInputs]store.OwnerRef
		exclusive := true
		for i := range known {
			var refs [store.MaxSnapshotOwners]store.OwnerRef
			found, complete := lookupReader(inputs[i], refs[:])
			if !complete || found != 1 || !refs[0].Exclusive ||
				i > 0 && !sameOwner(refs[0], proofs[0]) {
				exclusive = false
				break
			}
			proofs[i] = refs[0]
		}
		if exclusive {
			if hook := joinHookForTest.Load(); hook != nil {
				(*hook)()
			}
			viaGuard := false
			for i := range known {
				viaGuard = viaGuard || proofs[i].ViaGuard
			}
			if owner, ok := proofs[0].Handle(); ok &&
				store.BindDerivedReaderValue(&owner, output, viaGuard, inputs[:known], proofs[:known]) {
				return
			}
		}
	}
	for i := range known {
		var refs [store.MaxSnapshotOwners]store.OwnerRef
		found, _ := lookupReader(inputs[i], refs[:])
		bindReaderOwners(refs[:found], output)
	}
}

// sameOwner reports whether a and b refer to the same owner slot and
// generation.
func sameOwner(a, b store.OwnerRef) bool {
	aIndex, aGeneration, _, aOK := a.Identity()
	bIndex, bGeneration, _, bOK := b.Identity()
	return aOK && bOK && aIndex == bIndex && aGeneration == bGeneration
}

// PropagateGuardedReader binds a wrapper output that user code can retarget
// (io.LimitReader, bufio.NewReaderSize) to the owners of input (see the Read
// guard in the internal/taint/store package doc). When a complete lookup finds
// exactly one owner of input, with an effectively exclusive binding, it adds a
// Read guard for output, then binds output exclusively, with viaGuard and with
// input as its input (rule (e)). In all other cases, the binding is not
// exclusive.
func PropagateGuardedReader(input, output any) {
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count, complete := lookupReader(input, refs[:])
	if complete && count == 1 && refs[0].Exclusive {
		if owner, ok := refs[0].Handle(); ok {
			if index, ok := owner.Index(); ok {
				// Publish the guard before the exclusive binding, so that an
				// effectively exclusive guarded binding never exists
				// without its guard.
				if iobridge.Guard(output, input, index, owner.Generation()) {
					if store.BindDerivedReaderValue(&owner, output, true, []any{input}, refs[:1]) {
						return
					}
					iobridge.Unguard(output)
				} else {
					owner.RecordGuardDrop()
				}
			}
		}
	}
	bindReaderOwners(refs[:count], output)
}

// ReaderToken is the exclusive owner of a reader at one lookup (reader binding
// rule (f)). A consumer takes it with ReaderOwner BEFORE the first byte of the
// reader flows, and checks it again with RevalidateReader AFTER the bytes
// flowed, at attribution time. The zero value is not OK.
type ReaderToken struct {
	token store.ReaderToken
}

// OK reports whether the lookup of the token found exactly one exclusive
// owner.
func (t ReaderToken) OK() bool { return t.token.OK }

// Identity returns the owner slot and generation of the token.
func (t ReaderToken) Identity() (index uint8, generation uint64, ok bool) {
	if !t.token.OK {
		return 0, 0, false
	}
	return t.token.Index, t.token.Generation, true
}

// ReaderOwner returns the owner token of input. The token is OK only when a
// complete lookup finds exactly one active owner, with an effectively exclusive
// binding (rule (a2)). A consumer that attributes bytes of input must call
// RevalidateReader with the token after the bytes flowed: an OK token alone
// does not prove that the bytes that flowed after the lookup are data of the
// owner.
func ReaderOwner(input any) ReaderToken {
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count, complete := lookupReader(input, refs[:])
	if !complete || count != 1 {
		return ReaderToken{}
	}
	return ReaderToken{token: refs[0].ReaderToken()}
}

// RevalidateReader reports whether the owner of token is still the exclusive
// owner of input, with the same binding, and with no reader bind of another
// owner of input (or of an input of input, rule (e)) since that binding was
// made (rule (f), the creation baseline). A bind of another owner that
// started and ended before this call gives false, also when it ended before
// ReaderOwner took the token. A rebind of input by the owner of the token
// does not.
func RevalidateReader(token ReaderToken, input any) bool {
	_, ok := revalidateReader(token.token, input)
	return ok
}

// revalidateHookForTest runs in revalidateReader before the lookup. Only
// tests set it.
var revalidateHookForTest atomic.Pointer[func()]

// revalidateReader does a new complete lookup of input, and returns its only
// ref when token accepts it (store.ReaderToken.Revalidate).
func revalidateReader(token store.ReaderToken, input any) (store.OwnerRef, bool) {
	if !token.OK {
		return store.OwnerRef{}, false
	}
	if hook := revalidateHookForTest.Load(); hook != nil {
		(*hook)()
	}
	var refs [store.MaxSnapshotOwners]store.OwnerRef
	count, complete := lookupReader(input, refs[:])
	if !complete || count != 1 || !token.Revalidate(refs[0]) {
		return store.OwnerRef{}, false
	}
	return refs[0], true
}

// readAllOwner is the iobridge Owner callback (io.ReadAll, before the first
// read).
func readAllOwner(input any) iobridge.ReadToken {
	token := ReaderOwner(input).token
	if !token.OK {
		return iobridge.ReadToken{}
	}
	return iobridge.ReadToken{
		Store: token.Store, Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true,
	}
}

// readAllEnd is the iobridge ReadAll callback (io.ReadAll, after the reads).
func readAllEnd(input any, data []byte, token iobridge.ReadToken) {
	owner, _ := token.Store.(*store.Store)
	if !token.OK || owner == nil {
		return
	}
	ReadAllBytesForToken(ReaderToken{token: store.ReaderToken{
		Store: owner, Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true,
	}}, input, data)
}

// retargetHookForTest runs in retargetReader before it sets the bit. Only
// tests set it.
var retargetHookForTest atomic.Pointer[func()]

// retargetReader sets the retargeted bit of a process store owner. The Read
// guard of iobridge calls it when a guarded wrapper got a new target.
func retargetReader(index uint8, generation uint64) {
	if hook := retargetHookForTest.Load(); hook != nil {
		(*hook)()
	}
	if manager := processManager.Load(); manager != nil {
		store.MarkRetargeted(manager.store, index, generation)
	}
}

// CloneReaderBytes takes the owner token of input, and then calls
// CloneReaderBytesForToken. Thus it returns a clone only when input has
// exactly one effectively exclusive owner. Only tests call it, as a probe: a
// consumer must take the token before the first byte of input flows
// (ReaderOwner, ReaderOwnerToken).
func CloneReaderBytes(input any, data []byte) []byte {
	return CloneReaderBytesForToken(ReaderOwner(input), input, data)
}

// ReaderOwnerToken returns the owner token of reader in the form of the JSON
// bridge (jsonbridge.ReaderBinding.Capture, at NewDecoder). It is
// ReaderOwner: the token is OK only when a complete lookup finds exactly one
// active owner, with an effectively exclusive binding.
func ReaderOwnerToken(reader any) jsonbridge.OwnerToken {
	token := ReaderOwner(reader).token
	if !token.OK {
		return jsonbridge.OwnerToken{}
	}
	return jsonbridge.OwnerToken{
		Store: token.Store, Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true,
	}
}

// CloneForOwner is the Clone callback of the JSON bridge. A decoder calls it
// for each value that it read from reader, with the token that ReaderOwnerToken
// returned when the decoder was made. proven is false when the token is not
// valid for reader any more (RevalidateReader, rule (f)): then the decoder
// never propagates again. Else it adopts an exact-capacity clone of data into
// the owner of token only, and returns it. When data is too short or larger
// than the root limit, or when the adoption fails, it returns (nil, true): a
// miss for this value only. An oversized value with a valid token counts a drop
// for that owner only.
func CloneForOwner(reader any, token jsonbridge.OwnerToken, data []byte) (clone []byte, proven bool) {
	owner, _ := token.Store.(*store.Store)
	if !token.OK || owner == nil {
		return nil, false
	}
	if len(data) < 2 {
		return nil, true
	}
	ref, ok := revalidateReader(store.ReaderToken{
		Store: owner, Generation: token.Generation, Index: token.Index, Entry: token.Entry, OK: true,
	}, reader)
	if !ok {
		return nil, false
	}
	if len(data) > store.MaxRootBytes {
		if handle, ok := ref.Handle(); ok {
			handle.RecordBytesDrop()
		}
		return nil, true
	}
	analysis, ok := analysisForOwner(ref)
	if !ok {
		return nil, false
	}
	clone = make([]byte, len(data))
	copy(clone, data)
	if !analysis.adoptBodyBytes(clone) {
		return nil, true
	}
	return clone, true
}

// CloneReaderBytesForToken returns an exact-capacity clone of data, read from
// input, and attempts to publish it for the owner of token only. The caller
// takes token with ReaderOwner BEFORE the first byte of data flowed. It
// returns nil when token is not OK, when the owner of token is not the
// exclusive owner of input any more (RevalidateReader), or when data exceeds
// the root limit.
func CloneReaderBytesForToken(token ReaderToken, input any, data []byte) []byte {
	if !token.token.OK || len(data) < 2 || len(data) > store.MaxRootBytes {
		return nil
	}
	ref, ok := revalidateReader(token.token, input)
	if !ok {
		return nil
	}
	analysis, ok := analysisForOwner(ref)
	if !ok {
		return nil
	}
	clone := make([]byte, len(data))
	copy(clone, data)
	analysis.adoptBodyBytes(clone)
	return clone
}

// ReadAllBytes takes the owner token of input, and then calls
// ReadAllBytesForToken. Only tests call it: the io.ReadAll aspect takes the
// token before the first read (iobridge.ReadAllBegin).
func ReadAllBytes(input any, data []byte) {
	ReadAllBytesForToken(ReaderOwner(input), input, data)
}

// ReadAllBytesForToken adopts an io.ReadAll result of input into the owner of
// token only, without changing the result slice. The caller takes token before
// the first read. When the owner of token is not the exclusive owner of input
// any more (RevalidateReader), it is a miss. An oversized result counts a drop
// for that owner only.
func ReadAllBytesForToken(token ReaderToken, input any, data []byte) {
	if !token.token.OK || len(data) < 2 {
		return
	}
	ref, ok := revalidateReader(token.token, input)
	if !ok {
		return
	}
	if len(data) > store.MaxRootBytes || cap(data) > store.MaxRootBytes {
		if owner, ok := ref.Handle(); ok {
			owner.RecordBytesDrop()
		}
		return
	}
	if analysis, ok := analysisForOwner(ref); ok {
		analysis.adoptBodyBytes(data)
	}
}

func (a Analysis) adoptBodyBytes(data []byte) bool {
	if !a.Active() || !a.slot.sourceMu.TryLock() {
		return false
	}
	defer a.slot.sourceMu.Unlock() // +checklocksforce: TryLock.
	if !a.Active() {
		return false
	}
	result, token := a.slot.table.prepareBytes(constants.OriginHttpRequestBody, "", data)
	if result.Status != AddAdded && result.Status != AddDuplicate {
		return false
	}
	owner := a.slot.owner.Load()
	if owner == nil || owner.Disabled() {
		return false
	}
	if result.Status == AddDuplicate {
		var set ranges.Set
		if !ranges.AdoptCanonical(
			&set,
			ranges.DefaultLimit,
			[]ranges.Range{{Length: uint32(len(data)), SourceID: result.ID}},
			uint32(cap(data)),
		).Valid {
			return false
		}
		_, ok := owner.AdoptBytes(data, &set)
		return ok
	}
	managedName, managedValue, _, ok := owner.AdoptSourceBytes(data, "", result.ID)
	if !ok {
		return false
	}
	a.slot.table.commit(token, Source{
		Origin: constants.OriginHttpRequestBody,
		Name:   managedName, Value: managedValue, Kind: SourceBytes,
	})
	return true
}
