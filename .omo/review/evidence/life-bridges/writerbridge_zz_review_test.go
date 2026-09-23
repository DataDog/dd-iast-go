package writerbridge

import "testing"

func TestReviewCallbackPanicReachesHost(t *testing.T) {
	old := registered.Load()
	t.Cleanup(func() { registered.Store(old) })
	Register(func(uintptr, uintptr, uintptr, bool) { panic("callback panic") }); activeStates.Store(1); t.Cleanup(func() { activeStates.Store(0) })
	got := func() (r any) {
		defer func() { r = recover() }()
		Invalidate(0x1000, 0, 0, Exposure)
		return nil
	}()
	t.Logf("panic escaping bridge into host: %v", got)
	if got == nil { t.Fatal("expected unshielded panic") }
}
