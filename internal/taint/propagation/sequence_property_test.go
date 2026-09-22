// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation_test

import (
	"math/rand/v2"
	"strings"
	"testing"

	"github.com/DataDog/dd-iast-go/internal/taint/propagation"
	"github.com/DataDog/dd-iast-go/internal/taint/ranges"
	"github.com/DataDog/dd-iast-go/internal/taint/store"
)

func TestEngineSequenceAgainstOracle(t *testing.T) {
	taintStore, _ := beginScope(t)
	random := rand.New(rand.NewPCG(0x1A57C0DE, 0x51CECAFE))
	var coverage [sequenceOperationN]int
	for iteration := 0; iteration < 2_000; iteration++ {
		encoded := make([]byte, 64+random.IntN(sequenceMaxInput-63))
		for index := range encoded {
			encoded[index] = byte(random.Uint64())
		}
		observed := runEngineSequence(t, taintStore, encoded)
		for operation := range coverage {
			coverage[operation] += observed[operation]
		}
	}
	for operation, count := range coverage {
		if count == 0 {
			t.Fatalf("fixed-seed generator did not exercise operation %d", operation)
		}
	}
}

func TestCoarseTransitionUsesFirstContributorAndMarkIntersectionPerOwner(t *testing.T) {
	taintStore, _ := beginScope(t)
	owners := [sequenceOwnerCount]*store.Owner{taintStore.Acquire(), taintStore.Acquire()}
	for ownerIndex, owner := range owners {
		if owner.Disabled() {
			t.Fatalf("owner %d admission unexpectedly failed", ownerIndex)
		}
		t.Cleanup(owner.Finish)
	}

	firstCells := [sequenceOwnerCount][]sequenceCell{
		partialSequenceCells(len("first"), 1, 4, 3, 0xe),
		partialSequenceCells(len("first"), 0, 2, 7, 0xe),
	}
	secondCells := [sequenceOwnerCount][]sequenceCell{
		partialSequenceCells(len("second"), 2, 6, 4, 0x6),
		partialSequenceCells(len("second"), 1, 5, 8, 0xa),
	}
	first := adoptSequenceValue(t, owners, sequenceString, []byte("first"), firstCells)
	second := adoptSequenceValue(t, owners, sequenceString, []byte("second"), secondCells)

	native := strings.Join([]string{first.text, second.text}, "/")
	out := propagation.CoarseString(native, first.text, second.text)
	if out != native {
		t.Fatalf("CoarseString changed native value: got %q want %q", out, native)
	}
	result := sequenceValue{kind: sequenceString, text: out}
	result.cells[0] = wholeSequenceCells(len(out), 3, 0x6)
	result.cells[1] = wholeSequenceCells(len(out), 7, 0xa)
	assertSequenceValue(t, taintStore, owners, result, "coarse contributor fixture")
}

func TestCoarseTransitionHonorsSixteenInputInspectionBound(t *testing.T) {
	taintStore, _ := beginScope(t)
	owners := [sequenceOwnerCount]*store.Owner{taintStore.Acquire(), taintStore.Acquire()}
	for ownerIndex, owner := range owners {
		if owner.Disabled() {
			t.Fatalf("owner %d admission unexpectedly failed", ownerIndex)
		}
		t.Cleanup(owner.Finish)
	}

	cells := [sequenceOwnerCount][]sequenceCell{
		wholeSequenceCells(len("tainted"), 5, 0xa),
		make([]sequenceCell, len("tainted")),
	}
	managed := adoptSequenceValue(t, owners, sequenceString, []byte("tainted"), cells)
	inputs := make([]string, 17)
	for index := range inputs {
		inputs[index] = "clean-value"
	}
	inputs[16] = managed.text

	native := "bounded-result"
	dropped := propagation.CoarseString(native, inputs...)
	if dropped != native {
		t.Fatalf("out-of-bound coarse input changed native value: got %q want %q", dropped, native)
	}
	clean := sequenceValue{kind: sequenceString, text: dropped}
	clean.cells[0] = make([]sequenceCell, len(dropped))
	clean.cells[1] = make([]sequenceCell, len(dropped))
	assertSequenceValue(t, taintStore, owners, clean, "coarse input bound drop")

	inputs[15] = managed.text
	includedNative := "included-result"
	included := propagation.CoarseString(includedNative, inputs...)
	if included != includedNative {
		t.Fatalf("in-bound coarse input changed native value: got %q want %q", included, includedNative)
	}
	result := sequenceValue{kind: sequenceString, text: included}
	result.cells[0] = wholeSequenceCells(len(included), 5, 0xa)
	result.cells[1] = make([]sequenceCell, len(included))
	assertSequenceValue(t, taintStore, owners, result, "last inspected coarse input")
}

func TestCoarseJoinDropsLateElementAndRetainsReservedSeparator(t *testing.T) {
	taintStore, _ := beginScope(t)
	owners := [sequenceOwnerCount]*store.Owner{taintStore.Acquire(), taintStore.Acquire()}
	for ownerIndex, owner := range owners {
		if owner.Disabled() {
			t.Fatalf("owner %d admission unexpectedly failed", ownerIndex)
		}
		t.Cleanup(owner.Finish)
	}

	lateCells := [sequenceOwnerCount][]sequenceCell{
		wholeSequenceCells(len("late"), 9, 0xe),
		make([]sequenceCell, len("late")),
	}
	late := adoptSequenceValue(t, owners, sequenceString, []byte("late"), lateCells)
	separatorCells := [sequenceOwnerCount][]sequenceCell{
		wholeSequenceCells(len("::"), 10, 0x6),
		make([]sequenceCell, len("::")),
	}
	separator := adoptSequenceValue(t, owners, sequenceString, []byte("::"), separatorCells)
	elements := make([]string, 17)
	for index := range elements {
		elements[index] = "x"
	}
	elements[15] = late.text

	cleanNative := strings.Join(elements, "-")
	cleanOut := propagation.JoinString(elements, "-", cleanNative)
	clean := sequenceValue{kind: sequenceString, text: cleanOut}
	clean.cells[0] = make([]sequenceCell, len(cleanOut))
	clean.cells[1] = make([]sequenceCell, len(cleanOut))
	assertSequenceValue(t, taintStore, owners, clean, "late join contributor drop")

	separatorNative := strings.Join(elements, separator.text)
	separatorOut := propagation.JoinString(elements, separator.text, separatorNative)
	result := sequenceValue{kind: sequenceString, text: separatorOut}
	result.cells[0] = wholeSequenceCells(len(separatorOut), 10, 0x6)
	result.cells[1] = make([]sequenceCell, len(separatorOut))
	assertSequenceValue(t, taintStore, owners, result, "reserved separator contributor")
}

func partialSequenceCells(length, low, high int, source ranges.SourceID, marks uint64) []sequenceCell {
	cells := make([]sequenceCell, length)
	for index := low; index < high; index++ {
		cells[index] = sequenceCell{tainted: true, source: source, marks: marks}
	}
	return cells
}

func wholeSequenceCells(length int, source ranges.SourceID, marks uint64) []sequenceCell {
	return partialSequenceCells(length, 0, length, source, marks)
}
