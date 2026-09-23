package main

import (
	"encoding/json"
	"strings"
)

func main() {
	var destination struct {
		Value string `json:"value"`
	}
	_ = json.NewDecoder(strings.NewReader(`{"value":"secret"}`)).Decode(&destination)
}
