package main

import (
	"fmt"

	"github.com/zzz/initcrash2/fp"
)

func main() {
	fmt.Println("fingerprint:", fp.Fingerprint()[:12], "valid:", fp.Valid("abc"))
}
