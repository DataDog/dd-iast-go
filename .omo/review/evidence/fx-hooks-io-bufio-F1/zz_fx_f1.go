package testapp

import (
	"bufio"
	"io"
)

var fxPool = make(chan *bufio.Reader, 1)

// FxReadAllPooled mirrors the net/http newBufioReader pooling idiom
// (reuse via Reset, construct on miss) with a deterministic pool.
func FxReadAllPooled(src io.Reader) string {
	var br *bufio.Reader
	select {
	case br = <-fxPool:
		br.Reset(src)
	default:
		br = bufio.NewReader(src)
	}
	data, _ := io.ReadAll(br)
	br.Reset(nil)
	select {
	case fxPool <- br:
	default:
	}
	return string(data)
}

func BytesToStringForFx(data []byte) string { return string(data) }
