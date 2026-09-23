package perfsample

import "testing"

var sink int
var sinkS string
var sinkB bool

func BenchmarkSample(b *testing.B) {
	get := []byte("GET")
	src := []byte("hello world payload")
	b.Run("ConcatLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += ConcatLocal("GET", "/a")
		}
	})
	b.Run("ConvLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkB = ConvLocal(get)
		}
	})
	b.Run("ByteSliceLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += ByteSliceLocal(src)
		}
	})
	b.Run("StringSliceLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += StringSliceLocal(src)
		}
	})
	b.Run("BuilderLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sinkS = BuilderLocal("abc", "def")
		}
	})
	b.Run("BufferLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += BufferLocal("abc")
		}
	})
	b.Run("JoinLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += JoinLocal("abc", "def")
		}
	})
	b.Run("SprintfLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += SprintfLocal("abc")
		}
	})
	b.Run("CutLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += CutLocal("key=value")
		}
	})
	b.Run("TrimLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += TrimLocal("  abc  ")
		}
	})
	b.Run("SplitSeqLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += SplitSeqLocal("a,b,c")
		}
	})
	b.Run("FieldsSeqLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += FieldsSeqLocal("a b c")
		}
	})
	b.Run("QuoteLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += QuoteLocal("abc")
		}
	})
	b.Run("ToLowerLocal", func(b *testing.B) {
		b.ReportAllocs()
		for b.Loop() {
			sink += ToLowerLocal("abc")
		}
	})
}
