package httpbridge

import (
	"context"
	"testing"
)

func TestReviewCallbackPanicReachesHost(t *testing.T) {
	old, oldLazy := registered.Load(), registeredLazy.Load()
	t.Cleanup(func() { registered.Store(old); registeredLazy.Store(oldLazy) })
	Register(func(ctx context.Context) (context.Context, bool) { return ctx, true },
		func(context.Context, bool) { panic("finish panic") },
		func(context.Context, *string, *string, *string, map[string][]string, any, any) map[string][]string { panic("eager panic") })
	got := func() (r any) {
		defer func() { r = recover() }()
		Eager(context.Background(), nil, nil, nil, nil, nil, nil)
		return nil
	}()
	t.Logf("panic escaping bridge into net/http: %v", got)
	if got == nil { t.Fatal("expected unshielded panic") }
}
