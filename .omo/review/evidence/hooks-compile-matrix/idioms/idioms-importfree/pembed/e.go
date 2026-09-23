package pembed

import (
	"bytes"
	"strings"
)

type Doc struct {
	strings.Builder
	n int
}

type Out struct {
	*bytes.Buffer
}

type holder struct{ sb strings.Builder; bb bytes.Buffer }

func Build(s string) string {
	var d Doc
	d.WriteString(s)
	d.WriteByte('!')
	pd := &d
	pd.WriteString(s)
	o := Out{Buffer: new(bytes.Buffer)}
	o.WriteString(s)
	o.Write([]byte(s))
	h := &holder{}
	h.sb.WriteString(s)
	h.bb.WriteString(s)
	hs := []holder{{}}
	hs[0].sb.WriteString(s)
	return d.String() + "|" + o.String() + "|" + h.sb.String() + h.bb.String() + hs[0].sb.String()
}
