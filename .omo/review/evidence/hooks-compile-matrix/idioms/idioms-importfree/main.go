package main

import (
	"fmt"
	"os"

	"example.com/idioms/pcgo"
	"example.com/idioms/pconst"
	"example.com/idioms/pembed"
	"example.com/idioms/pflow"
	"example.com/idioms/pgeneric"
	"example.com/idioms/pmethod"
	"example.com/idioms/pnamed"
	"example.com/idioms/pslice"
	"example.com/idioms/pvariadic"
)

func main() {
	s := "a=b c%20d"
	if len(os.Args) > 1 {
		s = os.Args[1]
	}
	fmt.Println(pconst.Describe(pconst.Route), pconst.Describe(s))
	fmt.Println(pgeneric.Cat(pnamed.MyStr("x"), "y"), pgeneric.Cat3("a", "b", "c"), pgeneric.Add(1, 2), pgeneric.Add("p", "q"), pgeneric.Add(1.5, 2))
	fmt.Println(pgeneric.Head("hello", 2), string(pgeneric.Head([]byte("hello"), 3)), pgeneric.Tail([]int{1, 2, 3}, 1), pgeneric.ToStr(pnamed.MyBytes("zz")), pgeneric.ToBytes(pnamed.MyStr("qq")), pgeneric.SubStr(s))
	fmt.Println(pgeneric.Pair[int, pnamed.MyStr]{K: 1, V: "v"}.Join("+"))
	fmt.Println(pnamed.Ops("abc", pnamed.MyBytes("xyzw"), []pnamed.MyByte{'h', 'i'}, pnamed.MyRunes("rü")))
	fmt.Println(pnamed.Rune(0x263A))
	fmt.Println(pembed.Build(s))
	fmt.Println(pvariadic.Run(s, 1, "two"))
	fmt.Println(pslice.Ops(&pslice.T{Name: "name", Raw: []byte("raw")}, map[string]string{"k": "kv"}))
	fmt.Println(pflow.Flow(s))
	fmt.Println(pcgo.Hello(s))
	fmt.Println(pmethod.Run(s))
}
