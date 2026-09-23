package main

import (
	"crypto/md5"
	"fmt"

	"example.com/early"
	"github.com/acme/shop/digest"
	"github.com/acme/shop/legacy"
	"github.com/acme/shop/legacy2"
)

func main() {
	// Runtime (post-init) weak hash: must not crash.
	s := md5.Sum([]byte("runtime"))
	fmt.Printf("MAIN_OK fingerprint=%s des=%v early=%x runtime=%x probe=%s\n", digest.Fingerprint, legacy.Block != nil, early.Sum[:2], s[:2], legacy2.Probe)
}
