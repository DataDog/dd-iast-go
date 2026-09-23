package scopebridge

import "testing"

func TestReviewCallbackPanicReachesHost(t *testing.T) {
	old := registered.Load()
	t.Cleanup(func() { registered.Store(old) })
	Register(func(uint8, uint64, uint64) { panic("callback panic") })
	got := func() (r any) {
		defer func() { r = recover() }()
		Finish(0, 1, 1)
		return nil
	}()
	t.Logf("panic escaping bridge into host: %v", got)
	if got == nil {
		t.Fatal("expected unshielded panic")
	}
}
