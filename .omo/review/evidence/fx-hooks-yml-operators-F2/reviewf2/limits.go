package reviewf2

// Realistic customer shapes: untyped float constants used as slice bounds.
const maxLen = 1e3 // untyped float constant, integral value

// Truncate caps a string at maxLen bytes.
func Truncate(s string) string {
	if len(s) > maxLen {
		return s[:maxLen]
	}
	return s
}

// Header returns the first 2 bytes using an untyped float literal.
func Header(b []byte) []byte { return b[0:2.0] }

// Mid uses a complex-valued integral constant.
func Mid(s string) string { return s[complex(1, 0):3] }

// Full uses an untyped float max in a three-index slice.
func Full(b []byte) []byte { return b[0:2:4.0] }
