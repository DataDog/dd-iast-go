package reprosink

import (
	"github.com/DataDog/dd-iast-go/internal/vulnerability"
	"github.com/DataDog/dd-trace-go/v2/ddtrace/tracer"
)

// Query mirrors the woven database/sql advice: the sink report is deferred and
// runs when the host method returns OR while a driver panic unwinds.
func Query(span *tracer.Span, out *vulnerability.CapturedLocation, driver func()) {
	defer report(span, out)
	driver()
}

func report(span *tracer.Span, out *vulnerability.CapturedLocation) {
	*out = vulnerability.CaptureLocationSkipWhile(span, 1, vulnerability.SkipWhile{
		Namespaces: []string{"github.com/DataDog/dd-iast-go/internal/vulnerability"},
		MaxDepth:   32,
	})
}
