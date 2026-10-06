// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package request

import "unsafe"

// bodyRead is the propbridge BodyRead callback: when body is the registered
// body of an owner, it taints the n bytes at p, and records them in the owner
// (plan section 4.4). It does nothing for other objects (for example the body
// of a client response, which uses the same type).
func (m *Manager) bodyRead(body, p unsafe.Pointer, n uintptr) {
	defer func() { _ = recover() }()
	if !m.Active() || body == nil || n == 0 {
		return
	}
	m.forEachActive(func(s *slot, generation uint32, id uint64) bool {
		ref := s.body.Load()
		if ref == nil || ref.owner != id || unsafe.Pointer(ref.object.Value()) != body {
			return true
		}
		// The offset is in the registration, not in the locked data: a Read
		// that the lock drops still moves the offset (the copy then stops,
		// so that copy offsets stay equal to body offsets).
		offset := ref.offset.Add(uint64(n)) - uint64(n)
		located := bitsSet(p, n)
		m.use(s, generation, id, func(d *ownerData) {
			d.recordBody(p, n, offset, located)
		})
		return false
	})
}
