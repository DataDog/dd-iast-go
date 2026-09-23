package main

import (
	"encoding/json"
	"fmt"
	"strings"
)

func main() {
	var value struct{ Label string }
	err := json.NewDecoder(strings.NewReader(`{"Label":"independent-f1"}`)).Decode(&value)
	if err != nil {
		panic(err)
	}
	fmt.Println(value.Label)
}
