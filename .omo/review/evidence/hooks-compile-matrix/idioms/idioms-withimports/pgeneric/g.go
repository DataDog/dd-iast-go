package pgeneric

type Stringish interface{ ~string }
type Ordered interface {
	~int | ~int64 | ~float64 | ~string
}
type ByteSeq interface{ ~string | ~[]byte }

func Cat[T Stringish](a, b T) T        { return a + b }
func Cat3[T Stringish](a, b, c T) T    { return a + "-" + b + c }
func Add[T Ordered](a, b T) T          { return a + b }
func Head[T ByteSeq](s T, n int) T     { return s[:n] }
func Tail[S ~[]E, E any](s S, n int) S { return s[n:len(s):len(s)] }
func ToStr[B ~[]byte](b B) string      { s := string(b); return s }
func ToBytes[S ~string](s S) []byte    { b := []byte(s); return b }
func SubStr[S ~string](s S) string     { return string(s[1:]) }

type Pair[K comparable, V Stringish] struct {
	K K
	V V
}

func (p Pair[K, V]) Join(sep V) V { return p.V + sep + p.V }
