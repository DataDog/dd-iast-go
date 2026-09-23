// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

func (s *Store) allocateOverflow() uint16 {
	if !s.overflowMu.TryLock() {
		return 0
	}
	defer s.overflowMu.Unlock() // +checklocksforce: TryLock.
	if s.overflowN == 0 {
		return 0
	}
	s.overflowN--
	return s.overflowFree[s.overflowN] + 1
}

func (s *Store) freeOverflow(index uint16) {
	if index == 0 {
		return
	}
	s.overflowMu.Lock()
	s.freeOverflowLocked(index)
	s.overflowMu.Unlock()
}

func (s *Store) freeOverflowLocked(index uint16) {
	if index == 0 || int(s.overflowN) >= len(s.overflowFree) {
		return
	}
	block := index - 1
	clear(s.overflow[block].ranges[:])
	s.overflowFree[s.overflowN] = block
	s.overflowN++
}
