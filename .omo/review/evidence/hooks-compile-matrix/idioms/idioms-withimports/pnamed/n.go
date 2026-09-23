package pnamed

type MyStr string
type MyBytes []byte
type MyByte byte
type MyRunes []rune

func Ops(a MyStr, b MyBytes, c []MyByte, r MyRunes) (MyStr, string, string, string, MyBytes, string, string) {
	x := a + "!" + a
	y := string(b)
	z := string(c)
	w := string(r)
	v := b[1:2:3]
	u := string(a[1:])
	var q MyStr = "k" + a
	return x, y, z, w, v, u, string(q)
}

func Rune(n int) string { s := string(rune(n)); return s }
