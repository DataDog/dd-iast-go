package store

import "sync/atomic"

// fxReviewSeamOnce is a review-only hook invoked between the generation load
// and the state load inside Owner.alive(), preserving the original load order.
// It is nil unless a review test installs it; production builds never set it.
var fxReviewSeamOnce atomic.Pointer[func()]

// fxInstallSeam installs a one-shot hook and returns a restore function.
func fxInstallSeam(hook func()) (restore func()) {
	fxReviewSeamOnce.Store(&hook)
	return func() { fxReviewSeamOnce.Store(nil) }
}
