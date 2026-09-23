package pflow

import (
	"fmt"
	"sync"
)

func Flow(s string) string {
	var mu sync.Mutex
	var wg sync.WaitGroup
	res := ""
	ch := make(chan string, 1)
	wg.Add(1)
	go func(v string) { defer wg.Done(); ch <- v }(s + "-go")
	select {
	case v := <-ch:
		mu.Lock()
		res = v + "|" + s
		mu.Unlock()
	}
	wg.Wait()
	defer fmt.Sprint(s + "-defer")
	fn := func() string { return s[1:] + res }
	return fn()
}
