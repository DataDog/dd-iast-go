// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

import (
	"sync"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/stretchr/testify/require"
)

func TestConcurrentReadersWritersAndFinish(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintString("0123456789abcdefghijklmnopqrstuvwxyz", 0)
	require.True(t, ok)
	key, _ := StringKey(managed)

	start := make(chan struct{})
	var wait sync.WaitGroup
	for worker := 0; worker < 8; worker++ {
		wait.Add(1)
		go func(offset int) {
			defer wait.Done()
			<-start
			for i := 0; i < 500; i++ {
				begin := (offset + i) % (len(managed) - 2)
				subKey, valid := StringKey(managed[begin : begin+2])
				if valid {
					owner.Derive(subKey, root)
				}
			}
		}(worker)
	}
	for range 8 {
		wait.Add(1)
		go func() {
			defer wait.Done()
			<-start
			var snapshot Snapshot
			for i := 0; i < 1_000; i++ {
				store.Lookup(key, &snapshot)
			}
		}()
	}
	close(start)
	owner.Finish()
	wait.Wait()
	require.Zero(t, store.ProcessCharged())
	require.Zero(t, store.ProcessValues())
}

func TestLookupRacesMutationAndFinish(t *testing.T) {
	store := New()
	owner := store.Acquire()
	managed, root, ok := owner.TaintBytes([]byte("abcdefgh"), 0)
	require.True(t, ok)
	key, _ := BytesKey(managed)
	var wait sync.WaitGroup
	wait.Add(2)
	go func() {
		defer wait.Done()
		for i := 0; i < 200; i++ {
			managed[0]++
			var set ranges.Set
			ranges.AdoptCanonical(&set, 10, []ranges.Range{{Length: uint32(len(managed)), SourceID: 0}}, uint32(cap(managed)))
			if next, published := owner.PublishBytesMutation(root, managed, &set); published {
				root = next
			}
		}
	}()
	go func() {
		defer wait.Done()
		var snapshot Snapshot
		for i := 0; i < 1_000; i++ {
			store.Lookup(key, &snapshot)
		}
	}()
	wait.Wait()
	owner.Finish()
	require.Zero(t, store.ProcessValues())
}
