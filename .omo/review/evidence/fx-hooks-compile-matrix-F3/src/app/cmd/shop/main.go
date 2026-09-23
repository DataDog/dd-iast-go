package main

import (
	"fmt"

	"example.com/shop/internal/bconv"
	"example.com/shop/internal/buildinfo"
	"example.com/shop/internal/buildinfo2"
	"example.com/shop/internal/conv"
	"example.com/shop/internal/pure"
	"example.com/shop/internal/textutil"
)

func main() {
	fmt.Println(buildinfo.UserAgent(), buildinfo2.UserAgent(), textutil.Truncate("hello-world", 5), string(conv.Raw("id-1")), bconv.Key([]byte("k-2")), pure.Add(1, 2))
}
