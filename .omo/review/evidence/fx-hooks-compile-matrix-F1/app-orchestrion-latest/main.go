package main

import (
	"fmt"
	"net/http"
	"os"
)

func handler(w http.ResponseWriter, r *http.Request) {
	q := "SELECT * FROM t WHERE name = '" + r.URL.Query().Get("name") + "'"
	fmt.Fprintln(w, q)
}

func main() {
	http.HandleFunc("/", handler)
	fmt.Println("prefix-" + os.Args[0][:1])
}
