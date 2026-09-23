package iobridge

import "testing"

func TestReviewCallbackPanicReachesHost(t *testing.T) {
	old := registered.Load()
	t.Cleanup(func() { registered.Store(old) })
	Register(func(any, any) { panic("callback panic") }, func(any, []byte) { panic("callback panic") })
	got := func() (r any) {
		defer func() { r = recover() }()
		ReadAll(nil, nil)
		return nil
	}()
	t.Logf("panic escaping bridge into host: %v", got)
	if got == nil { t.Fatal("expected unshielded panic") }
}
