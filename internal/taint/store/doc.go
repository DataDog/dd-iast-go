// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

// Package store implements the bounded request-owned taint identity store.
// Numeric data addresses are comparison keys only and are never converted back
// to pointers. Strong managed roots are released synchronously when their owner
// finishes. Adoption APIs are only for audited results known to begin at their
// complete allocation base; ordinary callers must use cloning APIs.
//
// # Interior index
//
// The interior index finds the root that contains a value from any data
// pointer inside the root, not only from the root base. It replaces an older
// table of exact values.
//
// Footprint. The index and its filter are fixed arrays in Store: IndexShards
// shards of IndexBucketsPerShard buckets of IndexBucketSize entries (32 768
// entries; one key can use IndexBucketProbe buckets, thus 40 entries), and
// FilterBuckets filter counters. A root with a span of 2 to MaxSpanS bytes is
// in tier S (64-byte granules, at most 5 granules for each root). A larger
// root, up to MaxRootBytes, is in tier L (4 KiB granules, at most 17
// granules). Roots start at their allocation base and live allocations do not
// overlap, thus one granule key has at most 33 entries in tier S and 17
// entries in tier L. Both bounds are below the probe window. The index does
// not grow. When the probe window is full, the root admission fails (drop
// counter indexFull). TestStoreFootprint pins the size of Store.
//
// Entries. There is one entry for each (granule key, allocation base). An
// entry has at most MaxSnapshotOwners refs, and at most one ref for each
// owner. A ref of one more distinct owner is refused (drop counter fanout).
// A ref keeps the identity of a root (owner slot, low 32 bits of the owner
// generation, root ID), not its generation. A ref never changes its root ID.
//
// Admission is all or nothing. A root is visible to lookups only when
// root.indexed is true. A first adoption does these steps:
//
//   - step 0: look for a ref of this owner at the base key of each tier (tier
//     S first). A ref found means an extension (below), not a new root;
//   - steps 1 to 3: reserve the root slot, then add one ref in each granule
//     key, with TryLock only. On a failure, roll back and fail;
//   - step 4: add 1 to indexedRoots, then to the filter counter of each key;
//   - step 5: under rootsMu, check that the root generation did not change
//     and that no other root of this owner has a ref with the same base. Then
//     set root.indexed. On a failure, undo step 4 and roll back;
//   - step 6 (rollback): remove each added ref, then rollbackRoot.
//
// Extension. For one owner and one allocation base there is at most one root.
// A later adoption of the same allocation by the same owner extends that root
// in place (steps E1 to E5): E1 claims the extension right (owner.extending),
// E2 adds the refs of the new granule keys, E3 removes them on a failure, E4
// counts them and commits under rootsMu, and E5 removes the old tier S refs of
// a root that moved to tier L. The union rule gives the ranges of the
// extended root: on bytes that both range sets describe, the new ranges win;
// on all other bytes, each range is kept. Thus a re-adoption never removes
// taint. Only a tracked mutation (PublishBytesMutation) replaces ranges.
//
// Lookup and validation. A lookup reads tier S completely (filter load and
// shard probe) before it loads the tier L filter counter. An extension from
// tier S to tier L adds its tier L refs before it removes its tier S refs.
// Thus a lookup never misses a value of a root that moves. A filter counter of
// 0 proves that no visible root covers the granule. A reader copies the
// matching refs under the shard read lock, unlocks, and then validates each
// copy under rootsMu.TryRLock: the owner is active with the same generation,
// root.indexed is true, the base is the same, the value is inside the span,
// the root generation is not 0 and is equal to root.setGen, and the root has
// ranges. After the range copy, the root generation must not have changed.
// A mutation claims a new root generation, thus a lookup is a miss until the
// mutation publishes its ranges. For a mutation of an extended root with a
// smaller capacity, the ranges after that capacity stay only when they were
// valid just before the claim.
//
// Gate. indexedRoots is never lower than the number of roots with
// root.indexed set: the increment comes before root.indexed is set, and the
// decrement comes after root.indexed is cleared and the refs are removed. The
// runtime bridge gate mirrors indexedRoots (see the runtime hook rules in the
// internal/taint/runtimebridge package doc, rule 3).
//
// Locks. The lock order is rootsMu, then the shard lock. Readers only try the
// locks. Only rollback, the tier S clean-up of an extension (E5), and
// Owner.Finish wait on a shard lock.
//
// # Reader binding rules
//
// A reader binding attributes the bytes that a reader produces to one owner
// (a request). Consumers (the JSON decoders, io.ReadAll) attribute bytes only
// for a binding that is "effectively exclusive". These rules define it.
//
// Rule (a), exclusive flag. A reader binding is exclusive only when one of
// these is true when it is made:
//
//   - it is the HTTP request body binding at entry, or a request.BindReader
//     call (the caller asserts it). These are "root" bindings;
//   - it is a single-input wrapper that user code cannot retarget
//     (io.TeeReader, http.MaxBytesReader), and a complete lookup of its input
//     finds exactly one owner, with an effectively exclusive binding;
//   - it is an io.MultiReader with at most 8 inputs, and a complete lookup of
//     each input finds the same one owner, with an effectively exclusive
//     binding;
//   - it is a retargetable wrapper (io.LimitReader, bufio.NewReaderSize) with
//     the same input proof, and it has an entry in the Read guard table (see
//     the Read guard below). This binding is also "guarded" (viaGuard).
//
// All other bindings are not exclusive, for example an io.MultiReader with
// more than 8 inputs or with an input that is not bound, and the manual helper
// iast/bufio.Propagate (no Read guard). A new bind of the same reader keeps
// exclusive = old && new. A binding is guarded when it is guarded itself or
// when its input binding is guarded.
//
// Rule (a2), effective exclusivity. Each owner has a sticky "retargeted" bit. A
// lookup reports a binding as exclusive only when exclusive && !(viaGuard &&
// retargeted). All consumers and all wrapper proofs use this effective value.
// Fail closed: if the callback that sets the bit does not return normally,
// iobridge sets a process-wide sticky bit (iobridge.RetargetLost) before a byte
// of the new target flows. While it is set, no guarded binding is exclusive.
//
// Rule (b), complete lookups. A lookup that skipped an active owner (lock
// contention, or more owners than the output can hold) is not complete. An
// incomplete lookup is a miss. It never gives attribution, and it never makes
// an exclusive binding.
//
// Rule (d), identity is type plus address. Two different readers can have the
// same address (a struct and its first field). A binding records the dynamic
// type of the reader (the type word of the interface, read with no
// allocation) and its address. A lookup matches only the same type and the
// same address. This applies to all reader bindings.
//
// Rule (e), input revalidation. A "derived" exclusive binding is the binding
// of a wrapper. It records its inputs: the entries of the input bindings in
// the binding table of the same owner O (at most 8). A lookup reports it as
// effectively exclusive only when a complete lookup of each input finds
// exactly O, with the same entry and an effectively exclusive binding. This
// check is recursive, with a limit of 16 input lookups for each lookup. Over
// the limit, the result is a miss. Thus, when an input gets a second owner or
// stops being exclusive, each wrapper over it stops being exclusive before the
// next attribution. With rule (f), this loss is sticky: it stays after the
// second owner ends. A derived binding that gets no free input set is not
// exclusive.
//
// Rule (f), creation baseline and owner tokens. The loss of exclusivity is
// sticky for each reader binding, root or derived:
//
//   - Counters. Each store has 4,096 reader bind counters (Store.readerBinds).
//     A hash of the type word and the address of a reader selects its counter.
//     Each reader bind attempt of any owner adds 1 to the counter of its
//     reader, before the table change. A counter never decreases.
//   - Creation baseline. Each reader binding b keeps expect(b), the counter
//     value that the bind that made b got. Each later reader bind of the same
//     owner, under its table lock, adds 1 to expect of each reader binding of
//     the owner with the same counter.
//   - Invariant (I). C - expect(b) is the number of adds to the counter C since
//     b was made that are not binds of the same owner. A lookup reports b as
//     effectively exclusive only when C == expect(b), with C read under the
//     table read lock of the owner. Thus a bind of another owner makes b not
//     exclusive for good, also after the other owner ends. Two readers can
//     share a counter: this is a safe miss.
//   - One reader binding for each entry. An entry that stops being a reader
//     binding is "demoted": it never becomes exclusive again in this owner
//     generation. Thus an entry identifies at most one exclusive reader
//     binding, from its creation to its first loss.
//   - Tokens. A ReaderToken keeps the owner slot, the owner generation and
//     the binding entry of an effectively exclusive binding. Revalidation
//     does a new complete lookup. It must find exactly one active owner, with
//     the same slot, generation and entry, effectively exclusive.
//   - Consumers take a token before the first byte flows, and revalidate it
//     after the bytes flowed, at attribution time.
//
// Assumption (A1). A reader produces data of an owner only after the reader
// bind of that owner started (at the construction of the wrapper, or before
// the bytes flow).
//
// Assumption (A2), root content. A root reader gives only data of its owner
// for all the time that it is bound. A reset of a bound root to other data
// (for example strings.Reader.Reset on a reader of request.BindReader) keeps
// its address and its counter, thus no lookup can find it. This is outside
// the contract of request.BindReader. In production, the only root bind is
// the HTTP body at entry, and user code cannot reset the body types of the
// net/http server.
//
// Read guard. A retargetable wrapper (*io.LimitedReader, *bufio.Reader) can
// change its target (l.R = x, Reset, a value copy). The Read guard table of
// internal/taint/iobridge keeps the proven input of each guarded wrapper (at
// most 128 entries, with strong references). Each Read of the wrapper
// compares the current target with the proven input (type and address)
// before a byte flows. On a mismatch, it sets the retargeted bit of the owner
// and removes the entry. Then rule (a2) makes the wrapper, and each binding
// that depends on it, not exclusive. The guard entry is published before the
// exclusive binding, and it is removed when its owner finishes. If the table
// is full, the binding is not exclusive (a safe miss). Known limit: a copy of
// a bufio.Reader by value shares its buffer (see "Known limits" in the README).
//
// Consumers. io.ReadAll takes a token at entry and revalidates it at return.
// The v1 and v2 JSON decoders take a token at json.NewDecoder and revalidate
// it at each Decode. A binding that is made during the reads cannot claim the
// bytes that flowed before it.
package store
