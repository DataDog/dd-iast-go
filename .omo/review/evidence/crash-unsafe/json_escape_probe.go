package main

import "encoding/json"

func main() {
	var target struct {
		Value string `json:"value"`
	}
	_ = json.Unmarshal([]byte(`{"value":"attack"}`), &target)
}
