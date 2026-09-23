// Unless explicitly stated otherwise all files in this repository are licensed
// under the Apache License Version 2.0.
// This product includes software developed at Datadog (https://www.datadoghq.com/).
// Copyright 2026-present Datadog, Inc.

package propagation

import (
	"github.com/DataDog/dd-iast-go/internal/taint/operatorbridge"
	internal "github.com/DataDog/dd-iast-go/internal/taint/propagation"
)

type integer interface {
	~int | ~int8 | ~int16 | ~int32 | ~int64 | ~uint | ~uint8 | ~uint16 | ~uint32 | ~uint64 | ~uintptr
}

// Concat2 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat2[T ~string](a, b T) T {
	return concat2Result(a, b, a+b)
}

func concat2Result[T ~string](a, b T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat2(string(a), string(b), string(result)))
}

// Concat3 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat3[T ~string](a, b, c T) T {
	return concat3Result(a, b, c, a+b+c)
}

func concat3Result[T ~string](a, b, c T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat3(string(a), string(b), string(c), string(result)))
}

// Concat4 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat4[T ~string](a, b, c, d T) T {
	return concat4Result(a, b, c, d, a+b+c+d)
}

func concat4Result[T ~string](a, b, c, d T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat4(string(a), string(b), string(c), string(d), string(result)))
}

// Concat5 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat5[T ~string](a, b, c, d, e T) T {
	return concat5Result(a, b, c, d, e, a+b+c+d+e)
}

func concat5Result[T ~string](a, b, c, d, e T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat5(string(a), string(b), string(c), string(d), string(e), string(result)))
}

// Concat6 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat6[T ~string](a, b, c, d, e, f T) T {
	return concat6Result(a, b, c, d, e, f, a+b+c+d+e+f)
}

func concat6Result[T ~string](a, b, c, d, e, f T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat6(string(a), string(b), string(c), string(d), string(e), string(f), string(result)))
}

// Concat7 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat7[T ~string](a, b, c, d, e, f, g T) T {
	return concat7Result(a, b, c, d, e, f, g, a+b+c+d+e+f+g)
}

func concat7Result[T ~string](a, b, c, d, e, f, g T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat7(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(result)))
}

// Concat8 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat8[T ~string](a, b, c, d, e, f, g, h T) T {
	return concat8Result(a, b, c, d, e, f, g, h, a+b+c+d+e+f+g+h)
}

func concat8Result[T ~string](a, b, c, d, e, f, g, h T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat8(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(result)))
}

// Concat9 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat9[T ~string](a, b, c, d, e, f, g, h, i T) T {
	return concat9Result(a, b, c, d, e, f, g, h, i, a+b+c+d+e+f+g+h+i)
}

func concat9Result[T ~string](a, b, c, d, e, f, g, h, i T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat9(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(result)))
}

// Concat10 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat10[T ~string](a, b, c, d, e, f, g, h, i, j T) T {
	return concat10Result(a, b, c, d, e, f, g, h, i, j, a+b+c+d+e+f+g+h+i+j)
}

func concat10Result[T ~string](a, b, c, d, e, f, g, h, i, j T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat10(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(result)))
}

// Concat11 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat11[T ~string](a, b, c, d, e, f, g, h, i, j, k T) T {
	return concat11Result(a, b, c, d, e, f, g, h, i, j, k, a+b+c+d+e+f+g+h+i+j+k)
}

func concat11Result[T ~string](a, b, c, d, e, f, g, h, i, j, k T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat11(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(result)))
}

// Concat12 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat12[T ~string](a, b, c, d, e, f, g, h, i, j, k, l T) T {
	return concat12Result(a, b, c, d, e, f, g, h, i, j, k, l, a+b+c+d+e+f+g+h+i+j+k+l)
}

func concat12Result[T ~string](a, b, c, d, e, f, g, h, i, j, k, l T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat12(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(l), string(result)))
}

// Concat13 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat13[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m T) T {
	return concat13Result(a, b, c, d, e, f, g, h, i, j, k, l, m, a+b+c+d+e+f+g+h+i+j+k+l+m)
}

func concat13Result[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat13(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(l), string(m), string(result)))
}

// Concat14 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat14[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n T) T {
	return concat14Result(a, b, c, d, e, f, g, h, i, j, k, l, m, n, a+b+c+d+e+f+g+h+i+j+k+l+m+n)
}

func concat14Result[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat14(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(l), string(m), string(n), string(result)))
}

// Concat15 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat15[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n, o T) T {
	return concat15Result(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, a+b+c+d+e+f+g+h+i+j+k+l+m+n+o)
}

func concat15Result[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n, o T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat15(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(l), string(m), string(n), string(o), string(result)))
}

// Concat16 evaluates and propagates one fixed-arity maximal string concatenation.
func Concat16[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p T) T {
	return concat16Result(a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p, a+b+c+d+e+f+g+h+i+j+k+l+m+n+o+p)
}

func concat16Result[T ~string](a, b, c, d, e, f, g, h, i, j, k, l, m, n, o, p T, result T) T {
	if !operatorbridge.HasValues() {
		return result
	}
	return T(internal.Concat16(string(a), string(b), string(c), string(d), string(e), string(f), string(g), string(h), string(i), string(j), string(k), string(l), string(m), string(n), string(o), string(p), string(result)))
}

// BytesToString converts bytes and preserves exact taint ranges on the managed string result.
func BytesToString[T ~[]byte](value T) string {
	result := string(value)
	if !operatorbridge.HasValues() {
		return result
	}
	return internal.BytesToString([]byte(value), result)
}

// StringSliceAll performs a full string slice and derives its managed window.
func StringSliceAll[T ~string](value T) T {
	result := value[:]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.StringWindow(string(value), string(result))
	return result
}

// StringSliceLow performs a low-bounded string slice and derives its managed window.
func StringSliceLow[T ~string, L integer](value T, low L) T {
	result := value[low:]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.StringWindow(string(value), string(result))
	return result
}

// StringSliceHigh performs a high-bounded string slice and derives its managed window.
func StringSliceHigh[T ~string, H integer](value T, high H) T {
	result := value[:high]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.StringWindow(string(value), string(result))
	return result
}

// StringSliceBounds performs a bounded string slice and derives its managed window.
func StringSliceBounds[T ~string, L, H integer](value T, low L, high H) T {
	result := value[low:high]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.StringWindow(string(value), string(result))
	return result
}

// BytesSliceAll performs a full byte slice and derives its managed window.
func BytesSliceAll[T ~[]byte](value T) T {
	result := value[:]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}

// BytesSliceLow performs a low-bounded byte slice and derives its managed window.
func BytesSliceLow[T ~[]byte, L integer](value T, low L) T {
	result := value[low:]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}

// BytesSliceHigh performs a high-bounded byte slice and derives its managed window.
func BytesSliceHigh[T ~[]byte, H integer](value T, high H) T {
	result := value[:high]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}

// BytesSliceBounds performs a bounded byte slice and derives its managed window.
func BytesSliceBounds[T ~[]byte, L, H integer](value T, low L, high H) T {
	result := value[low:high]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}

// BytesSliceFull performs a three-index byte slice and derives its managed window.
func BytesSliceFull[T ~[]byte, L, H, M integer](value T, low L, high H, max M) T {
	result := value[low:high:max]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}

// BytesSliceFullZero performs a zero-low three-index byte slice and derives its managed window.
func BytesSliceFullZero[T ~[]byte, H, M integer](value T, high H, max M) T {
	result := value[:high:max]
	if !operatorbridge.HasValues() {
		return result
	}
	internal.ByteWindow([]byte(value), []byte(result))
	return result
}
