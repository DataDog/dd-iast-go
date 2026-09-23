package reviewf1

// CountSeparators models parsing a short HTTP header name without retaining it.
//
//go:noinline
func CountSeparators(raw []byte) int {
	name := string(raw)
	n := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '-' {
			n++
		}
	}
	return n
}

func returnedString(raw []byte) string {
	return string(raw)
}

// CountReturned models using a converted return value only within its caller.
//
//go:noinline
func CountReturned(raw []byte) int {
	name := returnedString(raw)
	n := 0
	for i := 0; i < len(name); i++ {
		if name[i] == '-' {
			n++
		}
	}
	return n
}
