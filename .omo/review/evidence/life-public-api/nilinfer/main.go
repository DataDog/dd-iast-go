package main

import (
	"github.com/DataDog/dd-iast-go/taint"
)

func main() {
	_ = taint.IsTaintedBytes(nil)
}
