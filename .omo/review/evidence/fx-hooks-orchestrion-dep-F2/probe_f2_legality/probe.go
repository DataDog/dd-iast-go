package probe_f2_legality

func strLow(s string) string        { return s[1.0:] }
func strHigh(s string) string       { return s[:2.0] }
func strBoth(s string) string       { return s[1.0:2.0] }
func bytLow(b []byte) []byte        { return b[1.0:] }
func bytHigh(b []byte) []byte       { return b[:2.0] }
func bytFull(b []byte) []byte       { return b[1.0:2.0:3.0] }
func strConstNamed(s string) string { return s[lo:] }

const lo = 1.0 // named untyped float constant

func cplx(s string) string { return s[1.0+0i:] }
