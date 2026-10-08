// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import "github.com/DataDog/dd-iast-go/internal/taint/store"

// The functions in this file adapt sink_bench_test.go to one store
// implementation. To compare with an older revision, run a copy of the
// benchmark on that revision, with a version of this file for its store (for
// example the exact-key value table).

const benchCapacity = store.IndexShards * store.IndexBucketsPerShard * store.IndexBucketSize

func benchOccupancy(s *store.Store) int { return int(s.Stats().IndexEntries) }

// benchProbes returns the number of index shards that a lookup of key reads.
func benchProbes(s *store.Store, key store.Key) int { return s.IndexProbes(key) }

// benchPublishWindow makes window, a window of the tainted root, visible to
// lookups. The interior index finds every window, so it has nothing to do.
func benchPublishWindow(*store.Store, string, string) bool { return true }
