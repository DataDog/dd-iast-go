package main

import (
	"fmt"

	"github.com/zzz/initorder/hasher"
)

func main() {
	fmt.Printf("started ok, seed=%x valid=%v\n", hasher.Seed[:4], hasher.Valid("x"))
}
