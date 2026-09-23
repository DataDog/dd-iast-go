package main

import (
	"fmt"
	"os"

	"github.com/DataDog/orchestrion/runtime/built"
)

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: reviewpin LEFT RIGHT")
		os.Exit(2)
	}

	fmt.Printf("woven=%t concat=%s\n", built.WithOrchestrion, os.Args[1]+os.Args[2])
}
