package jsonbridge

import "sync/atomic"

var ReviewDocNoReader, ReviewDocNoClone, ReviewDocStored, ReviewLitMapped, ReviewLitEnter, ReviewLitNoSlot, ReviewLitInactive, ReviewLitNoDoc, ReviewLitDocMismatch atomic.Int32

// ReviewOccupied is a review-only probe: it reports every occupied decoder slot.
func ReviewOccupied() (count int, pointers []uintptr, depths []uint32) {
	for index := range decoderStates {
		if pointer := decoderStates[index].pointer.Load(); pointer != 0 {
			count++
			pointers = append(pointers, pointer)
			depths = append(depths, decoderStates[index].depth.Load())
		}
	}
	return count, pointers, depths
}
