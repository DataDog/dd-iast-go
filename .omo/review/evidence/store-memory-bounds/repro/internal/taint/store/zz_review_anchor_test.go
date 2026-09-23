package store_test

import (
	"bytes"
	"context"
	"runtime"
	"testing"

	wrappers "github.com/DataDog/dd-iast-go/iast/propagation"
	"github.com/DataDog/dd-iast-go/internal/config"
	"github.com/DataDog/dd-iast-go/internal/model/constants"
	"github.com/DataDog/dd-iast-go/internal/taint/request"
	"github.com/stretchr/testify/require"
)

//go:noinline
func reviewBindRealReader(ctx context.Context, size int, bind bool) bool {
	data := bytes.Repeat([]byte{'r'}, size)
	reader := bytes.NewReader(data)
	if bind {
		return request.BindReader(ctx, reader)
	}
	runtime.KeepAlive(reader)
	return true
}

//go:noinline
func reviewTrackInteriorBuffer(value string, size int, track bool) bool {
	data := bytes.Repeat([]byte{'b'}, size)
	buffer := bytes.NewBuffer(data[size/2 : size/2 : size/2+64])
	if track {
		n, err := wrappers.BufferWriteString(buffer, value)
		return n == len(value) && err == nil
	}
	_, err := buffer.WriteString(value)
	return err == nil
}

func TestBoundsRetainedAnchors(t *testing.T) {
	require.True(t, config.Enabled)
	require.Equal(t, 100, config.RequestSamplingPct)
	for _, kind := range []string{"reader", "buffer"} {
		for _, size := range []int{32 << 20, 96 << 20} {
			t.Run(kind+"/"+string(rune('0'+size/(32<<20))), func(t *testing.T) {
				ctx, scope, created := request.Begin(context.Background())
				require.True(t, created)
				a, ok := scope.Analysis()
				require.True(t, ok)
				value, ok := a.TaintString(constants.OriginHttpRequestParameter, "q", "xx")
				require.True(t, ok)
				active := request.ActiveStore()
				baseCharge := active.ProcessCharged()
				before := heapInuse()
				if kind == "reader" {
					require.True(t, reviewBindRealReader(ctx, size, false))
				} else {
					require.True(t, reviewTrackInteriorBuffer(value, size, false))
				}
				control := heapInuse()
				if kind == "reader" {
					require.True(t, reviewBindRealReader(ctx, size, true))
				} else {
					require.True(t, reviewTrackInteriorBuffer(value, size, true))
					require.True(t, active.HasWriterStates())
				}
				retained := heapInuse()
				delta := int64(retained) - int64(control)
				charge := active.ProcessCharged() - baseCharge
				t.Logf("kind=%s payload=%d baseline=%d control=%d retained=%d delta=%d incrementalCharge=%d",
					kind, size, before, control, retained, delta, charge)
				require.Greater(t, delta, int64(size)-(1<<20))
				if kind == "reader" {
					require.Zero(t, charge)
				} else {
					require.Equal(t, int64(64), charge)
				}
				scope.Finish()
				finished := heapInuse()
				t.Logf("kind=%s finish=%d released=%d charged=%d", kind, finished, int64(retained)-int64(finished), active.ProcessCharged())
				require.Greater(t, int64(retained)-int64(finished), int64(size)-(1<<20))
				require.Zero(t, active.ProcessCharged())
				runtime.KeepAlive(active)
			})
		}
	}
}
