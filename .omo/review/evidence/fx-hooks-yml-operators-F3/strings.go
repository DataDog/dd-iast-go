package review_f3

// Join is an ordinary import-free application helper. The operator aspect
// inserts an import that was not part of this package's compile importcfg.
func Join(left, right string) string {
	return left + right
}
