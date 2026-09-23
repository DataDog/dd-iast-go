// Package reviewoperatornative is excluded by the existing internal/** filter.
package reviewoperatornative

func LenConcat(a, b string) int { return len(a + b) }
func CompareConcat(a, b string) bool { return a + b == "abcdef" }
func LenConversion(b []byte) int { s := string(b); return len(s) }
func CompareConversion(b []byte) bool { return string(b) == "abcdef" }
func MapConversion(m map[string]int, b []byte) int { return m[string(b)] }

func StringBounds(s string, low int64, high uint64) string { return s[low:high] }
func BytesBounds(s []byte, low int64, high uint64) []byte { return s[low:high] }
func BytesFull(s []byte, low int64, high uint64, max uint32) []byte {
	return s[low:high:max]
}
func StringLow(s string, low uint64) string { return s[low:] }
func BytesFullZero(s []byte, high uint64, max uint32) []byte { return s[:high:max] }

func UnevaluatedLen(s string, high int) int { return len([1]string{s[:high]}) }
func UnevaluatedRange(s string, high int) int {
	count := 0
	for range [1]string{s[:high]} { count++ }
	return count
}
