// Direct call reproducing exactly what the woven template generates for
// `value[1.0:]`: iastprop.StringSliceLow(value, 1.0)
package main

import (
	"fmt"

	iastprop "github.com/DataDog/dd-iast-go/iast/propagation"
)

func main() {
	value := "abc"
	fmt.Println(iastprop.StringSliceLow(value, 1.0))
}
