package main

type Stringish interface {
	~string | ~int
	~string
}

type Bytesish interface {
	~[]byte | ~[]int
	~[]byte
}

func concat[T Stringish](v T) T     { return v + "!" }
func slice[T Stringish](v T) T      { return v[1:] }
func bslice[T Bytesish](v T) T      { return v[1:] }

func main() {
	println(len(concat("x")), len(slice("xy")), len(bslice([]byte("ab"))))
}
