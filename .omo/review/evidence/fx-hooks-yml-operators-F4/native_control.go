package reviewf4native

var (
	IntSink  int
	BoolSink bool
)

func ConcatLen(a, b string) {
	IntSink = len(a + b)
}

func ConcatCompare(a, b string) {
	BoolSink = a+b == "abcdef"
}

func ConversionLen(value []byte) {
	converted := string(value)
	IntSink = len(converted)
}
