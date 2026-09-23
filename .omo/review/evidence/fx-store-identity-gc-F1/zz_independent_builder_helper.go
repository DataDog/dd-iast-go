// Review-only woven call sites for the independent builder identity check.
package testapp

import "strings"

// IndependentBuilderWrite reaches supported direct strings.Builder calls.
func IndependentBuilderWrite(builder *strings.Builder, value string) string {
	builder.WriteString(value)
	return builder.String()
}

// IndependentBuilderString reaches a supported direct strings.Builder.String call.
func IndependentBuilderString(builder *strings.Builder) string {
	return builder.String()
}
