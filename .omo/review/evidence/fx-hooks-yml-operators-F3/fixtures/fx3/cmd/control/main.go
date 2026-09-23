package main

import (
	"fmt"

	"github.com/DataDog/dd-iast-go/fx3/nooperator"
	"github.com/DataDog/dd-iast-go/fx3/withimport"
)

func main() { fmt.Println(withimport.Hello("world"), nooperator.Answer()) }
