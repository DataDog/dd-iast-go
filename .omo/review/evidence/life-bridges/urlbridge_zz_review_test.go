package urlbridge

import "testing"

func TestReviewCallbackPanicReachesHost(t *testing.T) {
	old := registered.Load()
	t.Cleanup(func() { registered.Store(old) })
	Register(func(any, map[string][]string) map[string][]string { panic("callback panic") })
	got := func() (r any) {
		defer func() { r = recover() }()
		Query(nil, nil)
		return nil
	}()
	t.Logf("panic escaping bridge into host: %v", got)
	if got == nil {
		t.Fatal("expected unshielded panic")
	}
}
