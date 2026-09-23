package fxconstctx

// Each declaration is valid Go only because len(...) of an array operand without
// function calls is a constant expression.

func ConstLenSlice(s string) int {
	const n = len([1]string{s[1:]})
	return n
}

func ConstLenConcat(a, b string) int {
	const n = len([1]string{a + b})
	return n
}

func ArraySizeFromLen(b []byte) int {
	var arr [len([1][]byte{b[1:]})]byte
	return len(arr)
}
