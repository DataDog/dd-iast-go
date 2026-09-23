package pconst

import "fmt"

const Prefix = "api"
const Route = Prefix + "/" + "v1" // constant concat
const Letter = string(rune(65))   // constant conversion
const Sliced = len(Route + "x")   // constant len of concat

var arr [len(Prefix + "xx")]int // array length from constant concat

type Kind string

const K Kind = "a" + "b" // typed constant concat

func Describe(s string) string {
	switch s {
	case Prefix + "/x":
		return "x"
	case Route:
		return "route"
	}
	return fmt.Sprint(Route, Letter, Sliced, len(arr), K)
}
