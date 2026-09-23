// Package methodexpr contains valid Go that calls hooked writer methods through
// method expressions, e.g. (*bytes.Buffer).WriteString(buf, s).
package methodexpr

import (
	"bytes"
	"strings"
)

func BufferViaMethodExpr(s string) string {
	var b bytes.Buffer
	(*bytes.Buffer).WriteString(&b, s)
	return (*bytes.Buffer).String(&b)
}

func BuilderViaMethodExpr(s string) string {
	var b strings.Builder
	(*strings.Builder).WriteString(&b, s)
	return (*strings.Builder).String(&b)
}
