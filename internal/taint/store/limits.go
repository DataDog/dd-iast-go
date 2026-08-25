// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package store

const (
	MaxOwners           = 64
	ProcessValueLimit   = 16_384
	ProcessRootBytes    = 8 << 20
	RequestValueLimit   = 4_096
	RequestRootBytes    = 2 << 20
	MaxRootBytes        = 64 << 10
	MaxRootChargeBytes  = 3 * MaxRootBytes
	MaxRootsPerOwner    = 512
	MaxValuesPerRoot    = 256
	GuaranteedRanges    = 10
	MaxRanges           = 64
	OverflowBlocks      = 256
	Shards              = 256
	SlotsPerShard       = 128
	ProbeLimit          = 64
	compactionThreshold = 32
	overflowRanges      = MaxRanges - GuaranteedRanges
)

const tombstone = ^uintptr(0)

var sizeClasses = [...]int{
	8, 16, 24, 32, 48, 64, 80, 96, 112, 128, 144, 160, 176, 192, 208, 224, 240,
	256, 288, 320, 352, 384, 416, 448, 480, 512, 576, 640, 704, 768, 896, 1024,
	1088, 1152, 1280, 1408, 1536, 1792, 2048, 2304, 2688, 3072, 3200, 3456,
	4096, 4864, 5392, 6144, 6528, 6784, 6912, 8192, 9472, 9728, 10240, 10880,
	12288, 13568, 14336, 16384, 18432, 19072, 20480, 21760, 24576, 27264,
	28672, 32768,
}

func sizeClass(n int) int64 {
	if n <= 0 {
		return 0
	}
	if n <= 32_768 {
		for _, class := range sizeClasses {
			if class >= n {
				return int64(class)
			}
		}
	}
	const page = 8 << 10
	return int64((n + page - 1) / page * page)
}
