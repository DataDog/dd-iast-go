package pslice

type T struct{ Name string; Raw []byte }

func get() string { return "hello-world" }

func Ops(t *T, m map[string]string) []string {
	arr := [5]byte{'a', 'b', 'c', 'd', 'e'}
	pa := &arr
	var u8 uint8 = 1
	var up uintptr = 2
	const two int64 = 2
	out := []string{
		string(arr[1:3]),
		string(pa[u8:up]),
		string(arr[:two:4]),
		m["k"][1:],
		get()[6:],
		"literal"[2:],
		t.Name[1:],
		string(t.Raw[:1]),
	}
	bs := []byte(get())
	bytes := bs[2:]
	out = append(out, string(bytes))
	return out
}
